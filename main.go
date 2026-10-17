package main

import (
	"embed"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rob121/cannon/extension"
	"gorm.io/gorm"
)

//go:embed help/*.md
var helpFiles embed.FS

//go:embed all:templates
var templateFiles embed.FS

const (
	extensionName        = "cannon-ext-firewall-coraza-waf"
	extensionTitle       = "Coraza WAF"
	extensionDescription = "OWASP Coraza web application firewall with CRS v4, admin rule management, IP bans, and passthru mode."
	extensionVersion     = "0.2.2"
	updateURLBase        = "https://github.com/rob121/cannon-ext-firewall-coraza-waf/releases/download"
	defaultAdminMenu     = "Firewall"
	pageSize             = 25
)

func firewallConfigSchema() json.RawMessage {
	d := defaultFirewallSettings()
	doc := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mode": map[string]any{
				"type":        "string",
				"title":       "Mode",
				"description": "disabled skips inspection. passthru logs what would block but allows the request. enforce runs full CRS on every non-excluded request (CPU-heavy; use after tuning in passthru, preferably at the edge).",
				"enum":        []string{"disabled", "passthru", "enforce"},
				"default":     d.Mode,
			},
			"block_status": map[string]any{
				"type":        "integer",
				"title":       "Block HTTP Status",
				"description": "Status code returned when a request is blocked in enforce mode. Leave blank to use " + itoa(d.BlockStatus) + ".",
				"default":     d.BlockStatus,
				"minimum":     400,
				"maximum":     499,
			},
			"block_message": map[string]any{
				"type":        "string",
				"title":       "Block Message",
				"description": "Shown on the blocked response page. Leave blank to use the built-in default.",
				"default":     d.BlockMessage,
			},
			"ban_seconds": map[string]any{
				"type":        "integer",
				"title":       "Ban Duration (seconds)",
				"description": "After a block, deny further requests from the client IP for this many seconds. Leave blank for " + itoa(d.BanSeconds) + "; set 0 to disable bans.",
				"default":     d.BanSeconds,
				"minimum":     0,
			},
			"paranoia_level": map[string]any{
				"type":        "integer",
				"title":       "Paranoia Level",
				"description": "CRS blocking/detection paranoia level (1–4). Higher is stricter and noisier. Leave blank for " + itoa(d.ParanoiaLevel) + ".",
				"default":     d.ParanoiaLevel,
				"minimum":     1,
				"maximum":     4,
			},
			"inbound_anomaly_threshold": map[string]any{
				"type":        "integer",
				"title":       "Inbound Anomaly Threshold",
				"description": "CRS inbound anomaly score that triggers a block. Leave blank for " + itoa(d.InboundAnomalyThreshold) + ".",
				"default":     d.InboundAnomalyThreshold,
				"minimum":     1,
			},
			"outbound_anomaly_threshold": map[string]any{
				"type":        "integer",
				"title":       "Outbound Anomaly Threshold",
				"description": "CRS outbound anomaly score threshold. Leave blank for " + itoa(d.OutboundAnomalyThreshold) + ".",
				"default":     d.OutboundAnomalyThreshold,
				"minimum":     1,
			},
			"exclude_admin": map[string]any{
				"type":        "boolean",
				"title":       "Skip /admin",
				"description": "Do not inspect Cannon admin paths (recommended).",
				"default":     d.ExcludeAdmin,
			},
			"exclude_paths": map[string]any{
				"type":        "string",
				"title":       "Excluded Path Prefixes",
				"description": "One path prefix per line (HasPrefix). Defaults skip theme/static assets so CRS is not paid on every CSS/JS hit.",
				"default":     d.ExcludePaths,
			},
			"max_body_bytes": map[string]any{
				"type":        "integer",
				"title":       "Max Request Body Inspected",
				"description": "Only the first N bytes of the body are sent to Coraza. Leave blank for " + itoa(d.MaxBodyBytes) + "; 0 uses whatever Cannon forwarded.",
				"default":     d.MaxBodyBytes,
				"minimum":     0,
			},
			"event_retention_days": map[string]any{
				"type":        "integer",
				"title":       "Event Retention (days)",
				"description": "Delete firewall events older than this many days. Leave blank for " + itoa(d.EventRetentionDays) + "; set 0 to keep forever. Expired IP bans are always purged.",
				"default":     d.EventRetentionDays,
				"minimum":     0,
			},
			"async_ban": map[string]any{
				"type":        "boolean",
				"title":       "Async Ban",
				"description": "Run full CRS off the request path and ban the IP for later requests when a hit is found. Does not block the current request (first malicious hit may reach the app). Sync ban-list checks still apply.",
				"default":     d.AsyncBan,
			},
			"async_ban_seconds": map[string]any{
				"type":        "integer",
				"title":       "Async Ban Duration (seconds)",
				"description": "Ban length after an async CRS hit. Leave blank or 0 to use Ban Duration (" + itoa(d.BanSeconds) + "). Set both to 0 to only log.",
				"default":     d.AsyncBanSeconds,
				"minimum":     0,
			},
			"async_ban_queue": map[string]any{
				"type":        "integer",
				"title":       "Async Ban Queue Size",
				"description": "Max pending CRS inspections. When full, new jobs are dropped (logged). Leave blank for " + itoa(d.AsyncBanQueue) + ".",
				"default":     d.AsyncBanQueue,
				"minimum":     1,
			},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return raw
}

var firewallConfigUI = json.RawMessage(`{
  "type": "VerticalLayout",
  "elements": [
    {"type": "Control", "scope": "#/properties/mode"},
    {"type": "Control", "scope": "#/properties/block_status"},
    {"type": "Control", "scope": "#/properties/block_message", "options": {"multi": true}},
    {"type": "Control", "scope": "#/properties/ban_seconds"},
    {"type": "Control", "scope": "#/properties/paranoia_level"},
    {"type": "Control", "scope": "#/properties/inbound_anomaly_threshold"},
    {"type": "Control", "scope": "#/properties/outbound_anomaly_threshold"},
    {"type": "Control", "scope": "#/properties/exclude_admin"},
    {"type": "Control", "scope": "#/properties/exclude_paths", "options": {"multi": true}},
    {"type": "Control", "scope": "#/properties/max_body_bytes"},
    {"type": "Control", "scope": "#/properties/event_retention_days"},
    {"type": "Group", "label": "Async Ban", "elements": [
      {"type": "Control", "scope": "#/properties/async_ban"},
      {"type": "Control", "scope": "#/properties/async_ban_seconds"},
      {"type": "Control", "scope": "#/properties/async_ban_queue"}
    ]}
  ]
}`)

func itoa(n int) string {
	return strconv.Itoa(n)
}

type firewallApp struct {
	info          extension.Info
	templates     *extension.Templates
	settingsTable string
	rulesTable    string
	eventsTable   string
	bansTable     string

	mu              sync.RWMutex
	engine          *wafEngine
	banMemo         sync.Map // ip -> unix expiry (active ban)
	banNegative     sync.Map // ip -> unix until which "not banned" is trusted
	banRecheckAt    sync.Map // ip -> unix last disk recheck
	bannedLogAt     sync.Map // ip -> unix last banned event log
	lastRetentionAt time.Time
	testDB          *gorm.DB // optional; used by unit tests

	siteDBmu     sync.Mutex
	siteDBConn   *gorm.DB
	wafDBmu      sync.Mutex
	wafDBConn    *gorm.DB
	wafStorePath string

	settingsMu     sync.RWMutex
	settingsCache  firewallSettings
	settingsCached bool

	eventCh chan eventRow

	asyncCh      chan asyncInspectJob
	asyncOnce    sync.Once
	asyncDropAt  sync.Map // rate-limit async_drop logs
	asyncWorkers int
	asyncPending int32 // accepted jobs not yet finished (tests + idle wait)
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "unban", "list-bans":
			if err := runCLI(os.Args[1], os.Args[2:]); err != nil {
				log.Fatal(err)
			}
			return
		}
	}
	_, s := newServer()
	if err := s.Run(); err != nil {
		log.Fatal(err)
	}
}

func newServer() (*firewallApp, *extension.Server) {
	info := extension.Info{
		Name:          extensionName,
		Title:         extensionTitle,
		Description:   extensionDescription,
		Version:       extensionVersion,
		UpdateURLBase: updateURLBase,
		AdminMenuName: defaultAdminMenu,
	}
	app := &firewallApp{
		info:          info,
		templates:     extension.NewTemplates(templateFiles, "templates"),
		settingsTable: extension.TableName(info.TablePrefix(), "settings"),
		rulesTable:    extension.TableName(info.TablePrefix(), "rules"),
		eventsTable:   extension.TableName(info.TablePrefix(), "events"),
		bansTable:     extension.TableName(info.TablePrefix(), "bans"),
	}

	s := extension.New(info)
	s.EmbedHelp(helpFiles, "help")
	s.EmbedTemplates(templateFiles, "templates")
	s.OnInstall(app.install)
	s.RegisterPermissions([]extension.PermissionDef{
		{ID: "firewall.view", DisplayName: "View firewall", Description: "View WAF status, rules, and events.", Category: "firewall"},
		{ID: "firewall.manage", DisplayName: "Manage firewall", Description: "Change mode, rules, bans, and preload CRS.", Category: "firewall", Dangerous: true},
	})
	s.OnConfiguration(extension.MapConfiguration([]extension.ConfigurationDefinition{
		{
			ID:       "general",
			Title:    "Firewall",
			Schema:   firewallConfigSchema(),
			UISchema: firewallConfigUI,
		},
	}, configStore{table: app.settingsTable, app: app}))

	s.HandleRequest("/request", app.handleRequest)
	s.HandleAdmin("/admin/", app.admin)
	app.startDiskWorkers()
	app.startRetentionLoop()
	app.startAsyncWorkers()
	return app, s
}

func (app *firewallApp) install(req extension.WireRequest) error {
	db, err := app.siteDB()
	if err != nil {
		return err
	}
	if err := app.migrateTables(db); err != nil {
		return err
	}
	if _, err := app.wafDB(); err != nil {
		return err
	}
	return app.rebuildEngine()
}

func (app *firewallApp) render(name string, data map[string]any) extension.WireResponse {
	body, err := app.templates.Execute(name, data)
	if err != nil {
		return extension.Error(http.StatusInternalServerError, err.Error())
	}
	return extension.HTML(http.StatusOK, body)
}

func adminHomeURL() string {
	return "/admin/extension-apps/" + url.PathEscape(extensionName)
}

func adminRoute(path string) (base string, parts []string) {
	path = strings.TrimSpace(path)
	marker := "/admin/extension-apps/" + extensionName
	idx := strings.Index(path, marker)
	if idx < 0 {
		return "", nil
	}
	base = path[:idx+len(marker)]
	rest := strings.Trim(path[idx+len(marker):], "/")
	if rest == "" {
		return base, nil
	}
	return base, strings.Split(rest, "/")
}

func parseID(s string) (uint, bool) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint(n), true
}

func parsePage(u *url.URL) int {
	page, _ := strconv.Atoi(u.Query().Get("page"))
	if page < 1 {
		return 1
	}
	return page
}

func csrfField(req extension.WireRequest) template.HTML {
	return template.HTML(extension.CSRFHiddenField(req))
}

func formValues(body string) (url.Values, error) {
	return url.ParseQuery(body)
}
