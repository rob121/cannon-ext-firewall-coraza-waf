package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestNewServerCapabilities(t *testing.T) {
	app, s := newServer()
	if app == nil || s == nil {
		t.Fatal("expected app and server")
	}
	if app.rulesTable != "firewall_coraza_waf_rules" {
		t.Fatalf("rules table = %q", app.rulesTable)
	}
	if !strings.Contains(crsVersion(), "4.") {
		t.Fatalf("unexpected CRS version %q", crsVersion())
	}
}

func TestSettingsNormalized(t *testing.T) {
	cfg := firewallSettings{Mode: "block", BlockStatus: 200}.normalized()
	if cfg.Mode != "enforce" {
		t.Fatalf("mode = %q", cfg.Mode)
	}
	if cfg.BlockStatus != 403 {
		t.Fatalf("block status = %d", cfg.BlockStatus)
	}
}

func TestIsBannedRechecksDBAfterMemoHit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:ban_memo_recheck?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	app := &firewallApp{
		bansTable: "firewall_coraza_waf_bans",
		testDB:    db,
	}
	if err := db.Table(app.bansTable).AutoMigrate(&banRow{}); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().UTC().Add(10 * time.Minute)
	app.banMemo.Store("1.2.3.4", exp.Unix())
	// Memo says banned, but no DB row (CLI/SQL unban).
	banned, _ := app.isBanned("1.2.3.4")
	if banned {
		t.Fatal("expected unbanned after DB row missing")
	}
	if _, ok := app.banMemo.Load("1.2.3.4"); ok {
		t.Fatal("expected memo cleared")
	}
	if _, ok := app.banNegative.Load("1.2.3.4"); !ok {
		t.Fatal("expected negative cache after clean disk recheck")
	}
	// Clear negative cache so a newly written ban is visible immediately.
	app.banNegative.Delete("1.2.3.4")
	if err := db.Table(app.bansTable).Create(&banRow{
		IP:        "1.2.3.4",
		Reason:    "test",
		ExpiresAt: exp,
		CreatedAt: time.Now().UTC(),
	}).Error; err != nil {
		t.Fatal(err)
	}
	banned, until := app.isBanned("1.2.3.4")
	if !banned {
		t.Fatal("expected banned when DB row exists")
	}
	if until.IsZero() {
		t.Fatal("expected expiry")
	}
}

func TestIsBannedNegativeCacheSkipsDisk(t *testing.T) {
	app := &firewallApp{bansTable: "firewall_coraza_waf_bans"}
	// Force fail if disk were consulted (no testDB / wafDB).
	app.banNegative.Store("9.9.9.9", time.Now().Add(banNegativeTTL).Unix())
	banned, _ := app.isBanned("9.9.9.9")
	if banned {
		t.Fatal("expected not banned from negative cache")
	}
}

func TestEventRetentionDefault(t *testing.T) {
	d := defaultFirewallSettings()
	if d.EventRetentionDays != 30 {
		t.Fatalf("EventRetentionDays = %d", d.EventRetentionDays)
	}
	raw := string(firewallConfigSchema())
	if !strings.Contains(raw, `"default":30`) {
		t.Fatalf("schema missing event retention default: %s", raw)
	}
	zero := firewallSettings{EventRetentionDays: -1}.normalized()
	if zero.EventRetentionDays != 0 {
		t.Fatalf("negative retention normalized to %d", zero.EventRetentionDays)
	}
}

func TestSanitizeSettingsMapDropsEmptyNumbers(t *testing.T) {
	data := map[string]any{
		"mode":           "passthru",
		"max_body_bytes": "",
		"ban_seconds":    float64(10),
		"block_message":  "",
	}
	sanitizeSettingsMap(data)
	if _, ok := data["max_body_bytes"]; ok {
		t.Fatal("expected empty max_body_bytes removed")
	}
	if _, ok := data["block_message"]; ok {
		t.Fatal("expected empty block_message removed so default applies")
	}
	if data["ban_seconds"] != float64(10) {
		t.Fatalf("ban_seconds = %#v", data["ban_seconds"])
	}
}

func TestFirewallConfigSchemaDefaultsMatchCode(t *testing.T) {
	d := defaultFirewallSettings()
	raw := string(firewallConfigSchema())
	for _, want := range []string{
		`"default":"passthru"`,
		`"default":403`,
		`"default":300`,
		`"default":1`,
		`"default":5`,
		`"default":4`,
		`"default":true`,
		`"default":131072`,
		d.BlockMessage,
		"/theme",
		"/assets",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("schema missing %q in %s", want, raw)
		}
	}
	if d.Mode != "passthru" || d.BlockStatus != 403 || d.BanSeconds != 300 || d.ParanoiaLevel != 1 ||
		d.InboundAnomalyThreshold != 5 || d.OutboundAnomalyThreshold != 4 || !d.ExcludeAdmin || d.MaxBodyBytes != 131072 {
		t.Fatalf("unexpected code defaults: %+v", d)
	}
	if d.ExcludePaths != defaultExcludePaths {
		t.Fatalf("ExcludePaths default = %q", d.ExcludePaths)
	}
}

func TestShouldSkipPath(t *testing.T) {
	cfg := defaultFirewallSettings().normalized()
	if !shouldSkipPath(cfg, "/admin/users") {
		t.Fatal("expected admin skip")
	}
	if !shouldSkipPath(cfg, "/theme/site.css") {
		t.Fatal("expected theme skip")
	}
	if !shouldSkipPath(cfg, "/static/app.js") {
		t.Fatal("expected static skip")
	}
	if shouldSkipPath(cfg, "/blog") {
		t.Fatal("blog should not skip")
	}
}

func TestIsResponseCRSFile(t *testing.T) {
	if !isResponseCRSFile("@owasp_crs/RESPONSE-950-DATA-LEAKAGES.conf") {
		t.Fatal("expected RESPONSE pack")
	}
	if isResponseCRSFile("@owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf") {
		t.Fatal("REQUEST pack should not be response")
	}
}

func TestPreloadCRSDisablesResponsePacks(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:preload_resp?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	app := &firewallApp{
		settingsTable: "firewall_coraza_waf_settings",
		rulesTable:    "firewall_coraza_waf_rules",
		eventsTable:   "firewall_coraza_waf_events",
		bansTable:     "firewall_coraza_waf_bans",
		testDB:        db,
	}
	// Seed a RESPONSE pack that was incorrectly enabled by an older preload.
	if err := app.migrateTables(db); err != nil {
		t.Fatal(err)
	}
	if err := db.Table(app.rulesTable).Create(&ruleRow{
		Kind:    ruleKindFile,
		Key:     "@owasp_crs/RESPONSE-950-DATA-LEAKAGES.conf",
		Title:   "RESPONSE-950-DATA-LEAKAGES",
		Enabled: true,
		Sort:    1,
		Source:  "crs",
	}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := app.preloadCRS(); err != nil {
		t.Fatal(err)
	}
	var rows []ruleRow
	if err := db.Table(app.rulesTable).Where("kind = ?", ruleKindFile).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	var sawResp, sawReq bool
	for _, r := range rows {
		if isResponseCRSFile(r.Key) {
			sawResp = true
			if r.Enabled {
				t.Fatalf("RESPONSE pack still enabled: %s", r.Key)
			}
		} else if strings.Contains(r.Key, "REQUEST-") && r.Enabled {
			sawReq = true
		}
	}
	if !sawResp {
		t.Fatal("expected RESPONSE packs after preload")
	}
	if !sawReq {
		t.Fatal("expected enabled REQUEST packs after preload")
	}
}

func TestBlockResponseStops(t *testing.T) {
	app := &firewallApp{}
	resp := app.blockResponse(firewallSettings{BlockStatus: 403, BlockMessage: "Nope"}.normalized(), "Nope")
	if resp.StatusCode != http.StatusForbidden || !resp.Stop {
		t.Fatalf("status=%d stop=%v", resp.StatusCode, resp.Stop)
	}
	if !strings.Contains(resp.Body, "Nope") {
		t.Fatalf("body=%q", resp.Body)
	}
}

func TestListCRSFiles(t *testing.T) {
	files, err := listCRSFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 10 {
		t.Fatalf("expected CRS files, got %d", len(files))
	}
	found := false
	for _, f := range files {
		if strings.Contains(f, "REQUEST-942") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing SQLi rule file in %#v", files)
	}
}

func TestInspectRequestBlocksXSS(t *testing.T) {
	app := &firewallApp{
		settingsTable: "firewall_coraza_waf_settings",
		rulesTable:    "firewall_coraza_waf_rules",
		eventsTable:   "firewall_coraza_waf_events",
		bansTable:     "firewall_coraza_waf_bans",
	}
	// Build a temporary engine with CRS includes (no DB).
	files, err := listCRSFiles()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("Include @coraza.conf-recommended\nInclude @crs-setup.conf.example\nSecRuleEngine On\n")
	b.WriteString(`SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=1,setvar:tx.detection_paranoia_level=1,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"` + "\n")
	for _, f := range files {
		if strings.HasPrefix(strings.TrimPrefix(f, "@owasp_crs/"), "REQUEST-") {
			b.WriteString("Include " + f + "\n")
		}
	}
	eng, err := buildTestEngine(b.String())
	if err != nil {
		t.Fatal(err)
	}
	app.engine = eng
	res := inspectRequest(eng, http.MethodGet, "http://example.com/?q=<script>alert(1)</script>", map[string][]string{
		"User-Agent": {"Mozilla/5.0"},
		"Host":       {"example.com"},
	}, "", "1.2.3.4")
	if !res.Interrupted {
		t.Fatalf("expected interrupt, matched=%v msgs=%v", res.RuleIDs, res.Messages)
	}
}
