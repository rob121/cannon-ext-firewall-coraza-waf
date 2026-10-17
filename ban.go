package main

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

func (app *firewallApp) isBanned(ip string) (bool, time.Time) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false, time.Time{}
	}
	now := time.Now().Unix()
	if v, ok := app.banMemo.Load(ip); ok {
		exp, _ := v.(int64)
		if exp <= now {
			app.banMemo.Delete(ip)
			return false, time.Time{}
		}
		// Trust memory on the hot path; periodically recheck disk so CLI unban works.
		if app.shouldRecheckBan(ip, now) {
			return app.recheckBanOnDisk(ip)
		}
		return true, time.Unix(exp, 0).UTC()
	}
	return app.recheckBanOnDisk(ip)
}

func (app *firewallApp) shouldRecheckBan(ip string, now int64) bool {
	if v, ok := app.banRecheckAt.Load(ip); ok {
		if last, _ := v.(int64); now-last < int64(banRecheckInterval/time.Second) {
			return false
		}
	}
	return true
}

func (app *firewallApp) recheckBanOnDisk(ip string) (bool, time.Time) {
	app.banRecheckAt.Store(ip, time.Now().Unix())
	db, err := app.wafDB()
	if err != nil {
		if v, ok := app.banMemo.Load(ip); ok {
			exp, _ := v.(int64)
			if exp > time.Now().Unix() {
				return true, time.Unix(exp, 0).UTC()
			}
		}
		return false, time.Time{}
	}
	var row banRow
	err = db.Table(app.bansTable).Where("ip = ? AND expires_at > ?", ip, time.Now().UTC()).First(&row).Error
	if err != nil {
		app.banMemo.Delete(ip)
		return false, time.Time{}
	}
	app.banMemo.Store(ip, row.ExpiresAt.Unix())
	return true, row.ExpiresAt.UTC()
}

func (app *firewallApp) banIP(ip, reason string, seconds int) {
	ip = strings.TrimSpace(ip)
	if ip == "" || seconds <= 0 {
		return
	}
	exp := time.Now().UTC().Add(time.Duration(seconds) * time.Second)
	app.banMemo.Store(ip, exp.Unix())
	go app.persistBan(ip, reason, exp)
}

func (app *firewallApp) persistBan(ip, reason string, exp time.Time) {
	db, err := app.wafDB()
	if err != nil {
		return
	}
	var existing banRow
	err = db.Table(app.bansTable).Where("ip = ?", ip).First(&existing).Error
	if err == gorm.ErrRecordNotFound {
		_ = db.Table(app.bansTable).Create(&banRow{
			IP:        ip,
			Reason:    reason,
			ExpiresAt: exp,
			CreatedAt: time.Now().UTC(),
		}).Error
		return
	}
	if err == nil {
		existing.Reason = reason
		existing.ExpiresAt = exp
		_ = db.Table(app.bansTable).Save(&existing).Error
	}
}

func (app *firewallApp) unbanIP(ip string) error {
	ip = strings.TrimSpace(ip)
	app.banMemo.Delete(ip)
	app.banRecheckAt.Delete(ip)
	db, err := app.wafDB()
	if err != nil {
		return err
	}
	return db.Table(app.bansTable).Where("ip = ?", ip).Delete(&banRow{}).Error
}

func (app *firewallApp) listActiveBans(db *gorm.DB) ([]banRow, error) {
	var rows []banRow
	err := db.Table(app.bansTable).
		Where("expires_at > ?", time.Now().UTC()).
		Order("expires_at asc").
		Find(&rows).Error
	return rows, err
}
