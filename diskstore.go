package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rob121/cannon/extension"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	wafStoreFileName     = "firewall_coraza_waf.sqlite"
	eventFlushInterval   = 250 * time.Millisecond
	eventFlushBatchSize  = 128
	eventChannelSize     = 4096
	banRecheckInterval   = 5 * time.Second
	bannedLogMinInterval = 30 * time.Second
)

func wafStorePath() (string, error) {
	site, err := extension.SiteConfig()
	if err != nil {
		return "", err
	}
	dsn := strings.TrimSpace(site.Database.DSN)
	if dsn == "" {
		return "", fmt.Errorf("site database dsn is empty")
	}
	dir := filepath.Dir(dsn)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, wafStoreFileName), nil
}

func openWafSQLite(path string) (*gorm.DB, error) {
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on", filepath.ToSlash(path))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	return db, nil
}

func (app *firewallApp) siteDB() (*gorm.DB, error) {
	if app.testDB != nil {
		return app.testDB, nil
	}
	app.siteDBmu.Lock()
	defer app.siteDBmu.Unlock()
	if app.siteDBConn != nil {
		return app.siteDBConn, nil
	}
	db, _, err := extension.OpenDB()
	if err != nil {
		return nil, err
	}
	app.siteDBConn = db
	return db, nil
}

func (app *firewallApp) wafDB() (*gorm.DB, error) {
	if app.testDB != nil {
		return app.testDB, nil
	}
	app.wafDBmu.Lock()
	defer app.wafDBmu.Unlock()
	if app.wafDBConn != nil {
		return app.wafDBConn, nil
	}
	path, err := wafStorePath()
	if err != nil {
		return nil, err
	}
	db, err := openWafSQLite(path)
	if err != nil {
		return nil, err
	}
	if err := app.migrateWafStore(db); err != nil {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			_ = sqlDB.Close()
		}
		return nil, err
	}
	app.wafDBConn = db
	app.wafStorePath = path
	return db, nil
}

func (app *firewallApp) migrateWafStore(db *gorm.DB) error {
	if err := db.Table(app.eventsTable).AutoMigrate(&eventRow{}); err != nil {
		return err
	}
	return db.Table(app.bansTable).AutoMigrate(&banRow{})
}

func (app *firewallApp) startDiskWorkers() {
	if app.eventCh == nil {
		app.eventCh = make(chan eventRow, eventChannelSize)
	}
	go app.eventFlushLoop()
	_ = app.loadBansIntoMemo()
	_ = app.importLegacySiteTablesOnce()
}

func (app *firewallApp) logEvent(ev eventRow) {
	ev.CreatedAt = time.Now().UTC()
	if ev.Action == "banned" && !app.allowBannedLog(ev.ClientIP) {
		return
	}
	if app.eventCh == nil {
		db, err := app.wafDB()
		if err != nil {
			return
		}
		_ = db.Table(app.eventsTable).Create(&ev).Error
		return
	}
	select {
	case app.eventCh <- ev:
	default:
		// Buffer full — drop rather than block the request path.
	}
}

func (app *firewallApp) allowBannedLog(ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return true
	}
	now := time.Now().Unix()
	if v, ok := app.bannedLogAt.Load(ip); ok {
		if last, _ := v.(int64); now-last < int64(bannedLogMinInterval/time.Second) {
			return false
		}
	}
	app.bannedLogAt.Store(ip, now)
	return true
}

func (app *firewallApp) eventFlushLoop() {
	buf := make([]eventRow, 0, eventFlushBatchSize)
	ticker := time.NewTicker(eventFlushInterval)
	defer ticker.Stop()
	flush := func() {
		if len(buf) == 0 {
			return
		}
		db, err := app.wafDB()
		if err == nil {
			_ = db.Table(app.eventsTable).CreateInBatches(buf, eventFlushBatchSize).Error
		}
		buf = buf[:0]
		app.maybeCleanupRetention()
	}
	for {
		select {
		case ev, ok := <-app.eventCh:
			if !ok {
				flush()
				return
			}
			buf = append(buf, ev)
			if len(buf) >= eventFlushBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (app *firewallApp) loadBansIntoMemo() error {
	db, err := app.wafDB()
	if err != nil {
		return err
	}
	var rows []banRow
	if err := db.Table(app.bansTable).Where("expires_at > ?", time.Now().UTC()).Find(&rows).Error; err != nil {
		return err
	}
	for _, row := range rows {
		app.banMemo.Store(row.IP, row.ExpiresAt.Unix())
	}
	return nil
}

// importLegacySiteTablesOnce copies events/bans from the site DB into the WAF
// disk store when the disk store is empty (one-time migration).
func (app *firewallApp) importLegacySiteTablesOnce() error {
	waf, err := app.wafDB()
	if err != nil {
		return err
	}
	var eventCount, banCount int64
	_ = waf.Table(app.eventsTable).Count(&eventCount).Error
	_ = waf.Table(app.bansTable).Count(&banCount).Error
	if eventCount > 0 || banCount > 0 {
		return nil
	}
	site, err := app.siteDB()
	if err != nil {
		return err
	}
	if !site.Migrator().HasTable(app.eventsTable) && !site.Migrator().HasTable(app.bansTable) {
		return nil
	}
	var events []eventRow
	_ = site.Table(app.eventsTable).Order("event_id asc").Limit(5000).Find(&events).Error
	if len(events) > 0 {
		_ = waf.Table(app.eventsTable).CreateInBatches(events, 100).Error
	}
	var bans []banRow
	_ = site.Table(app.bansTable).Where("expires_at > ?", time.Now().UTC()).Find(&bans).Error
	for _, b := range bans {
		app.banMemo.Store(b.IP, b.ExpiresAt.Unix())
		_ = waf.Table(app.bansTable).Create(&b).Error
	}
	return nil
}

// InvalidateSettingsCache drops the cached firewall settings.
func (app *firewallApp) InvalidateSettingsCache() {
	app.settingsMu.Lock()
	app.settingsCache = firewallSettings{}
	app.settingsCached = false
	app.settingsMu.Unlock()
}
