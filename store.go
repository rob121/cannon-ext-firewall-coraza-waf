package main

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/rob121/cannon/extension"
	"gorm.io/gorm"
)

const (
	ruleKindFile     = "file"
	ruleKindCustom   = "custom"
	ruleKindRemoveID = "remove_id"
)

type firewallSettings struct {
	Mode                     string `json:"mode"`
	BlockStatus              int    `json:"block_status"`
	BlockMessage             string `json:"block_message"`
	BanSeconds               int    `json:"ban_seconds"`
	ParanoiaLevel            int    `json:"paranoia_level"`
	InboundAnomalyThreshold  int    `json:"inbound_anomaly_threshold"`
	OutboundAnomalyThreshold int    `json:"outbound_anomaly_threshold"`
	ExcludeAdmin             bool   `json:"exclude_admin"`
	ExcludePaths             string `json:"exclude_paths"`
	MaxBodyBytes             int    `json:"max_body_bytes"`
	EventRetentionDays       int    `json:"event_retention_days"`
}

type ruleRow struct {
	ID         uint      `gorm:"primaryKey;column:rule_id"`
	Kind       string    `gorm:"column:kind;size:32;not null;uniqueIndex:idx_fw_rule_kind_key"`
	Key        string    `gorm:"column:rule_key;size:255;not null;uniqueIndex:idx_fw_rule_kind_key"`
	Title      string    `gorm:"column:title;size:255"`
	Directives string    `gorm:"column:directives;type:text"`
	Enabled    bool      `gorm:"column:enabled;not null;default:true;index"`
	Sort       int       `gorm:"column:sort;not null;default:0;index"`
	Source     string    `gorm:"column:source;size:32;not null;default:custom"`
	CreatedAt  time.Time `gorm:"column:created_at"`
	UpdatedAt  time.Time `gorm:"column:updated_at"`
}

type eventRow struct {
	ID        uint      `gorm:"primaryKey;column:event_id"`
	Action    string    `gorm:"column:action;size:32;not null;index"` // blocked | would_block | banned
	Mode      string    `gorm:"column:mode;size:32"`
	Method    string    `gorm:"column:method;size:16"`
	Path      string    `gorm:"column:path;size:1024"`
	ClientIP  string    `gorm:"column:client_ip;size:64;index"`
	Status    int       `gorm:"column:status"`
	RuleIDs   string    `gorm:"column:rule_ids;type:text"`
	Messages  string    `gorm:"column:messages;type:text"`
	CreatedAt time.Time `gorm:"column:created_at;index"`
}

type banRow struct {
	ID        uint      `gorm:"primaryKey;column:ban_id"`
	IP        string    `gorm:"column:ip;size:64;not null;uniqueIndex"`
	Reason    string    `gorm:"column:reason;type:text"`
	ExpiresAt time.Time `gorm:"column:expires_at;index"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

type configStore struct {
	table string
	app   *firewallApp
}

func (s configStore) openSiteDB() (*gorm.DB, error) {
	if s.app != nil {
		return s.app.siteDB()
	}
	db, _, err := extension.OpenDB()
	return db, err
}

func (s configStore) Load(section string) (map[string]any, error) {
	db, err := s.openSiteDB()
	if err != nil {
		return nil, err
	}
	return extension.DBConfigurationStore(db, s.table).Load(section)
}

func (s configStore) Save(section string, data map[string]any) error {
	db, err := s.openSiteDB()
	if err != nil {
		return err
	}
	if data != nil {
		delete(data, "_csrf")
		delete(data, "csrf")
	}
	if err := extension.DBConfigurationStore(db, s.table).Save(section, data); err != nil {
		return err
	}
	if s.app != nil {
		s.app.InvalidateSettingsCache()
		_ = s.app.rebuildEngine()
	}
	return nil
}

// migrateTables migrates settings/rules on the site DB. Events/bans live in the WAF disk store.
func (app *firewallApp) migrateTables(db *gorm.DB) error {
	if err := extension.MigrateConfigurationStore(db, app.settingsTable); err != nil {
		return err
	}
	return db.Table(app.rulesTable).AutoMigrate(&ruleRow{})
}

// defaultExcludePaths skips static/theme traffic that should not pay CRS cost.
const defaultExcludePaths = "/theme\n/assets\n/static\n/media\n/uploads\n/favicon.ico\n/robots.txt"

func defaultFirewallSettings() firewallSettings {
	return firewallSettings{
		Mode:                     "passthru",
		BlockStatus:              403,
		BlockMessage:             "Your request was blocked by the web application firewall.",
		BanSeconds:               300,
		ParanoiaLevel:            1,
		InboundAnomalyThreshold:  5,
		OutboundAnomalyThreshold: 4,
		ExcludeAdmin:             true,
		ExcludePaths:             defaultExcludePaths,
		MaxBodyBytes:             131072,
		EventRetentionDays:       30,
	}
}

func (app *firewallApp) loadSettings() (firewallSettings, error) {
	app.settingsMu.RLock()
	if app.settingsCached {
		cfg := app.settingsCache
		app.settingsMu.RUnlock()
		return cfg, nil
	}
	app.settingsMu.RUnlock()

	data, err := (configStore{table: app.settingsTable, app: app}).Load("general")
	if err != nil {
		return firewallSettings{}, err
	}
	cfg := defaultFirewallSettings()
	if len(data) > 0 {
		// Configuration forms often POST blank number fields as "". Drop those so
		// defaults remain instead of failing JSON unmarshal into int fields.
		sanitizeSettingsMap(data)
		raw, err := json.Marshal(data)
		if err != nil {
			return firewallSettings{}, err
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return firewallSettings{}, err
		}
	}
	cfg = cfg.normalized()
	app.settingsMu.Lock()
	app.settingsCache = cfg
	app.settingsCached = true
	app.settingsMu.Unlock()
	return cfg, nil
}

func sanitizeSettingsMap(data map[string]any) {
	if data == nil {
		return
	}
	for key, val := range data {
		switch v := val.(type) {
		case string:
			if strings.TrimSpace(v) == "" {
				delete(data, key)
			}
		case float64:
			// keep
		case json.Number:
			if strings.TrimSpace(v.String()) == "" {
				delete(data, key)
			}
		}
	}
}

func (cfg firewallSettings) normalized() firewallSettings {
	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
	case "enforce", "block", "on":
		cfg.Mode = "enforce"
	case "disabled", "off":
		cfg.Mode = "disabled"
	case "passthru", "detect", "detectiononly", "log":
		cfg.Mode = "passthru"
	default:
		if strings.TrimSpace(cfg.Mode) == "" {
			cfg.Mode = "passthru"
		} else {
			cfg.Mode = "passthru"
		}
	}
	if cfg.BlockStatus < 400 || cfg.BlockStatus > 499 {
		cfg.BlockStatus = 403
	}
	if strings.TrimSpace(cfg.BlockMessage) == "" {
		cfg.BlockMessage = "Your request was blocked by the web application firewall."
	}
	if cfg.BanSeconds < 0 {
		cfg.BanSeconds = 0
	}
	if cfg.ParanoiaLevel < 1 {
		cfg.ParanoiaLevel = 1
	}
	if cfg.ParanoiaLevel > 4 {
		cfg.ParanoiaLevel = 4
	}
	if cfg.InboundAnomalyThreshold < 1 {
		cfg.InboundAnomalyThreshold = 5
	}
	if cfg.OutboundAnomalyThreshold < 1 {
		cfg.OutboundAnomalyThreshold = 4
	}
	if cfg.MaxBodyBytes < 0 {
		cfg.MaxBodyBytes = 0
	}
	if cfg.EventRetentionDays < 0 {
		cfg.EventRetentionDays = 0
	}
	return cfg
}

func (cfg firewallSettings) excludePathList() []string {
	var out []string
	for _, line := range strings.Split(cfg.ExcludePaths, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func (app *firewallApp) listRules(db *gorm.DB) ([]ruleRow, error) {
	var rows []ruleRow
	err := db.Table(app.rulesTable).Order("kind asc, sort asc, rule_key asc").Find(&rows).Error
	return rows, err
}

func (app *firewallApp) maybeCleanupRetention() {
	const minInterval = 15 * time.Minute
	app.mu.Lock()
	last := app.lastRetentionAt
	if !last.IsZero() && time.Since(last) < minInterval {
		app.mu.Unlock()
		return
	}
	app.lastRetentionAt = time.Now().UTC()
	app.mu.Unlock()
	_, _, _ = app.runRetentionCleanup()
}

func (app *firewallApp) runRetentionCleanup() (eventsDeleted, bansDeleted int64, err error) {
	cfg, err := app.loadSettings()
	if err != nil {
		return 0, 0, err
	}
	db, err := app.wafDB()
	if err != nil {
		return 0, 0, err
	}
	now := time.Now().UTC()
	if cfg.EventRetentionDays > 0 {
		cutoff := now.AddDate(0, 0, -cfg.EventRetentionDays)
		res := db.Table(app.eventsTable).Where("created_at < ?", cutoff).Delete(&eventRow{})
		if res.Error != nil {
			return 0, 0, res.Error
		}
		eventsDeleted = res.RowsAffected
	}
	res := db.Table(app.bansTable).Where("expires_at < ?", now).Delete(&banRow{})
	if res.Error != nil {
		return eventsDeleted, 0, res.Error
	}
	bansDeleted = res.RowsAffected
	// Drop expired bans from the in-memory map too.
	app.banMemo.Range(func(key, value any) bool {
		exp, _ := value.(int64)
		if exp <= now.Unix() {
			app.banMemo.Delete(key)
		}
		return true
	})
	return eventsDeleted, bansDeleted, nil
}

func (app *firewallApp) startRetentionLoop() {
	go func() {
		// Initial pass shortly after process start.
		time.Sleep(5 * time.Second)
		if _, _, err := app.runRetentionCleanup(); err != nil {
			// OpenDB can fail before Cannon finishes wiring; ignore first pass errors.
		}
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			_, _, _ = app.runRetentionCleanup()
		}
	}()
}
