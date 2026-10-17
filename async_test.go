package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rob121/cannon/extension"
)

func testCRSEngine(t *testing.T) *wafEngine {
	t.Helper()
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
	return eng
}

func xssWireRequest(ip string) extension.WireRequest {
	return extension.WireRequest{
		Method: http.MethodGet,
		URL:    "http://example.com/?q=<script>alert(1)</script>",
		Header: map[string][]string{
			"User-Agent":      {"Mozilla/5.0"},
			"Host":            {"example.com"},
			"X-Forwarded-For": {ip},
		},
	}
}

func TestAsyncBanSettingsNormalized(t *testing.T) {
	d := defaultFirewallSettings()
	if d.AsyncBan || d.AsyncBanSeconds != 0 || d.AsyncBanQueue != 256 {
		t.Fatalf("defaults: %+v", d)
	}
	cfg := firewallSettings{AsyncBanSeconds: -5, AsyncBanQueue: 0}.normalized()
	if cfg.AsyncBanSeconds != 0 || cfg.AsyncBanQueue != 256 {
		t.Fatalf("normalized: %+v", cfg)
	}
	cfg = firewallSettings{BanSeconds: 300, AsyncBanSeconds: 0}.normalized()
	if cfg.asyncBanDuration() != 300 {
		t.Fatalf("asyncBanDuration = %d", cfg.asyncBanDuration())
	}
	cfg = firewallSettings{BanSeconds: 300, AsyncBanSeconds: 60}.normalized()
	if cfg.asyncBanDuration() != 60 {
		t.Fatalf("asyncBanDuration = %d", cfg.asyncBanDuration())
	}
	raw := string(firewallConfigSchema())
	for _, want := range []string{`"async_ban"`, `"async_ban_seconds"`, `"async_ban_queue"`, `"default":256`, `"default":false`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("schema missing %q", want)
		}
	}
}

func TestHandleRequestSyncBlocksXSS(t *testing.T) {
	app := &firewallApp{
		settingsTable: "firewall_coraza_waf_settings",
		rulesTable:    "firewall_coraza_waf_rules",
		eventsTable:   "firewall_coraza_waf_events",
		bansTable:     "firewall_coraza_waf_bans",
		engine:        testCRSEngine(t),
	}
	app.settingsCache = firewallSettings{
		Mode:       "enforce",
		AsyncBan:   false,
		BanSeconds: 60,
	}.normalized()
	app.settingsCached = true

	resp := app.handleRequest(xssWireRequest("198.51.100.10"))
	if !resp.Stop || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected sync block, stop=%v status=%d", resp.Stop, resp.StatusCode)
	}
}

func TestHandleRequestAsyncBansAfterWorker(t *testing.T) {
	app := &firewallApp{
		settingsTable: "firewall_coraza_waf_settings",
		rulesTable:    "firewall_coraza_waf_rules",
		eventsTable:   "firewall_coraza_waf_events",
		bansTable:     "firewall_coraza_waf_bans",
		engine:        testCRSEngine(t),
	}
	app.settingsCache = firewallSettings{
		Mode:            "enforce",
		AsyncBan:        true,
		AsyncBanSeconds: 120,
		AsyncBanQueue:   16,
		BanSeconds:      0,
		BlockStatus:     403,
	}.normalized()
	app.settingsCached = true
	app.startAsyncWorkers()

	ip := "198.51.100.20"
	resp := app.handleRequest(xssWireRequest(ip))
	if resp.Stop {
		t.Fatal("async path must not block the current request")
	}
	if !app.waitAsyncIdle(10 * time.Second) {
		t.Fatal("async queue did not drain")
	}
	if banned, _ := app.isBanned(ip); !banned {
		t.Fatal("expected IP banned after async CRS hit")
	}
}

func TestHandleRequestAsyncQueueFullDoesNotBlock(t *testing.T) {
	app := &firewallApp{
		settingsTable: "firewall_coraza_waf_settings",
		rulesTable:    "firewall_coraza_waf_rules",
		eventsTable:   "firewall_coraza_waf_events",
		bansTable:     "firewall_coraza_waf_bans",
		engine:        testCRSEngine(t),
		asyncWorkers:  -1,
	}
	app.settingsCache = firewallSettings{
		Mode:          "enforce",
		AsyncBan:      true,
		AsyncBanQueue: 1,
		BanSeconds:    60,
		BlockStatus:   403,
	}.normalized()
	app.settingsCached = true
	app.asyncCh = make(chan asyncInspectJob, 1)
	app.startAsyncWorkers()
	app.asyncCh <- asyncInspectJob{ClientIP: "filler", Mode: "enforce"}

	start := time.Now()
	resp := app.handleRequest(xssWireRequest("198.51.100.30"))
	elapsed := time.Since(start)
	if resp.Stop {
		t.Fatal("expected OK when queue drops newest")
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("handleRequest blocked for %s", elapsed)
	}
}

func TestHandleRequestBannedIPStillSyncBlocked(t *testing.T) {
	app := &firewallApp{
		settingsTable: "firewall_coraza_waf_settings",
		rulesTable:    "firewall_coraza_waf_rules",
		eventsTable:   "firewall_coraza_waf_events",
		bansTable:     "firewall_coraza_waf_bans",
		engine:        testCRSEngine(t),
	}
	app.settingsCache = firewallSettings{
		Mode:       "enforce",
		AsyncBan:   true,
		BanSeconds: 60,
	}.normalized()
	app.settingsCached = true
	ip := "198.51.100.40"
	app.banIP(ip, "prior", 300)

	resp := app.handleRequest(extension.WireRequest{
		Method: http.MethodGet,
		URL:    "http://example.com/",
		Header: map[string][]string{
			"Host":            {"example.com"},
			"X-Forwarded-For": {ip},
		},
	})
	if !resp.Stop || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected sync ban block, stop=%v status=%d", resp.Stop, resp.StatusCode)
	}
}
