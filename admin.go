package main

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rob121/cannon/extension"
	"gorm.io/gorm"
)

func (app *firewallApp) admin(req extension.WireRequest) extension.WireResponse {
	if !extension.UserAuthenticated(req) {
		return extension.Error(http.StatusForbidden, "sign in required")
	}
	canManage := adminCanManage(req)
	if !adminCanView(req) {
		return extension.Error(http.StatusForbidden, "permission denied")
	}
	db, err := app.siteDB()
	if err != nil {
		return extension.Error(http.StatusInternalServerError, err.Error())
	}
	if err := app.migrateTables(db); err != nil {
		return extension.Error(http.StatusInternalServerError, err.Error())
	}
	wafDB, err := app.wafDB()
	if err != nil {
		return extension.Error(http.StatusInternalServerError, err.Error())
	}

	adminURL, err := url.Parse(req.URL)
	if err != nil {
		return extension.Error(http.StatusBadRequest, err.Error())
	}
	basePath, parts := adminRoute(adminURL.Path)
	if basePath == "" {
		basePath = adminHomeURL()
	}
	csrf := csrfField(req)
	notice := adminURL.Query().Get("notice")
	errMsg := adminURL.Query().Get("error")

	switch {
	case len(parts) == 0:
		return app.adminHome(db, wafDB, basePath, notice, errMsg, csrf, canManage)
	case len(parts) == 1 && parts[0] == "rules":
		return app.listRulesAdmin(db, adminURL, basePath, notice, errMsg, csrf, canManage)
	case len(parts) == 2 && parts[0] == "rules" && parts[1] == "new":
		if !canManage {
			return extension.Error(http.StatusForbidden, "permission denied")
		}
		if strings.EqualFold(req.Method, http.MethodPost) {
			return app.saveRule(db, req.Body, basePath, 0, csrf)
		}
		return app.renderRuleForm(basePath, ruleRow{Kind: ruleKindCustom, Enabled: true, Source: "custom"}, true, "", csrf)
	case len(parts) == 2 && parts[0] == "rules":
		id, ok := parseID(parts[1])
		if !ok {
			return extension.Error(http.StatusNotFound, "rule not found")
		}
		if strings.EqualFold(req.Method, http.MethodPost) {
			if !canManage {
				return extension.Error(http.StatusForbidden, "permission denied")
			}
			return app.saveRule(db, req.Body, basePath, id, csrf)
		}
		return app.editRule(db, basePath, id, "", csrf)
	case len(parts) == 3 && parts[0] == "rules" && parts[2] == "toggle":
		if !canManage {
			return extension.Error(http.StatusForbidden, "permission denied")
		}
		if !strings.EqualFold(req.Method, http.MethodPost) {
			return extension.Error(http.StatusMethodNotAllowed, "POST required")
		}
		id, ok := parseID(parts[1])
		if !ok {
			return extension.Error(http.StatusNotFound, "rule not found")
		}
		var row ruleRow
		if err := db.Table(app.rulesTable).Where("rule_id = ?", id).First(&row).Error; err != nil {
			return extension.Error(http.StatusNotFound, "rule not found")
		}
		row.Enabled = !row.Enabled
		_ = db.Table(app.rulesTable).Save(&row).Error
		_ = app.rebuildEngine()
		return extension.Redirect(http.StatusSeeOther, basePath+"/rules?notice="+url.QueryEscape("Rule updated."))
	case len(parts) == 3 && parts[0] == "rules" && parts[2] == "delete":
		if !canManage {
			return extension.Error(http.StatusForbidden, "permission denied")
		}
		if !strings.EqualFold(req.Method, http.MethodPost) {
			return extension.Error(http.StatusMethodNotAllowed, "POST required")
		}
		id, ok := parseID(parts[1])
		if !ok {
			return extension.Error(http.StatusNotFound, "rule not found")
		}
		_ = db.Table(app.rulesTable).Where("rule_id = ?", id).Delete(&ruleRow{}).Error
		_ = app.rebuildEngine()
		return extension.Redirect(http.StatusSeeOther, basePath+"/rules?notice="+url.QueryEscape("Rule removed."))
	case len(parts) == 1 && parts[0] == "preload":
		if !canManage {
			return extension.Error(http.StatusForbidden, "permission denied")
		}
		if !strings.EqualFold(req.Method, http.MethodPost) {
			return extension.Error(http.StatusMethodNotAllowed, "POST required")
		}
		n, err := app.preloadCRS()
		if err != nil {
			return extension.Redirect(http.StatusSeeOther, basePath+"?error="+url.QueryEscape(err.Error()))
		}
		return extension.Redirect(http.StatusSeeOther, basePath+"?notice="+url.QueryEscape(fmt.Sprintf("Preloaded %d CRS v%s rule files.", n, crsVersion())))
	case len(parts) == 1 && parts[0] == "rebuild":
		if !canManage {
			return extension.Error(http.StatusForbidden, "permission denied")
		}
		if !strings.EqualFold(req.Method, http.MethodPost) {
			return extension.Error(http.StatusMethodNotAllowed, "POST required")
		}
		if err := app.rebuildEngine(); err != nil {
			return extension.Redirect(http.StatusSeeOther, basePath+"?error="+url.QueryEscape(err.Error()))
		}
		return extension.Redirect(http.StatusSeeOther, basePath+"?notice="+url.QueryEscape("WAF engine rebuilt."))
	case len(parts) == 1 && parts[0] == "events":
		return app.listEventsAdmin(wafDB, adminURL, basePath, notice, errMsg, csrf, canManage)
	case len(parts) == 2 && parts[0] == "events" && parts[1] == "cleanup":
		if !canManage {
			return extension.Error(http.StatusForbidden, "permission denied")
		}
		if !strings.EqualFold(req.Method, http.MethodPost) {
			return extension.Error(http.StatusMethodNotAllowed, "POST required")
		}
		eventsDeleted, bansDeleted, err := app.runRetentionCleanup()
		if err != nil {
			return extension.Redirect(http.StatusSeeOther, basePath+"/events?error="+url.QueryEscape(err.Error()))
		}
		msg := fmt.Sprintf("Cleanup removed %d event(s) and %d expired ban(s).", eventsDeleted, bansDeleted)
		return extension.Redirect(http.StatusSeeOther, basePath+"/events?notice="+url.QueryEscape(msg))
	case len(parts) == 1 && parts[0] == "bans":
		return app.listBansAdmin(wafDB, basePath, notice, csrf, canManage)
	case len(parts) == 2 && parts[0] == "bans" && parts[1] == "unban":
		if !canManage {
			return extension.Error(http.StatusForbidden, "permission denied")
		}
		if !strings.EqualFold(req.Method, http.MethodPost) {
			return extension.Error(http.StatusMethodNotAllowed, "POST required")
		}
		values, _ := formValues(req.Body)
		_ = app.unbanIP(values.Get("ip"))
		return extension.Redirect(http.StatusSeeOther, basePath+"/bans?notice="+url.QueryEscape("Ban removed."))
	default:
		return extension.Error(http.StatusNotFound, "admin route not found")
	}
}

func (app *firewallApp) adminHome(db, wafDB *gorm.DB, basePath, notice, errMsg string, csrf template.HTML, canManage bool) extension.WireResponse {
	cfg, _ := app.loadSettings()
	var ruleTotal, ruleEnabled, eventTotal, banTotal int64
	_ = db.Table(app.rulesTable).Count(&ruleTotal).Error
	_ = db.Table(app.rulesTable).Where("enabled = ?", true).Count(&ruleEnabled).Error
	_ = wafDB.Table(app.eventsTable).Count(&eventTotal).Error
	_ = wafDB.Table(app.bansTable).Where("expires_at > ?", time.Now().UTC()).Count(&banTotal).Error
	engReady := app.currentEngine() != nil
	return app.render("firewall/admin_home.html", map[string]any{
		"Title":       "Coraza WAF",
		"Subtitle":    "OWASP Coraza with CRS " + crsVersion(),
		"BasePath":    basePath,
		"SettingsURL": "/admin/configuration/extensions/" + url.PathEscape(extensionName),
		"Mode":        cfg.Mode,
		"BanSeconds":  cfg.BanSeconds,
		"RuleTotal":   ruleTotal,
		"RuleEnabled": ruleEnabled,
		"EventTotal":  eventTotal,
		"BanTotal":    banTotal,
		"EngineReady": engReady,
		"CRSVersion":  crsVersion(),
		"Notice":      notice,
		"Error":       errMsg,
		"CanManage":   canManage,
		"CSRFField":   csrf,
	})
}

func (app *firewallApp) listRulesAdmin(db *gorm.DB, adminURL *url.URL, basePath, notice, errMsg string, csrf template.HTML, canManage bool) extension.WireResponse {
	rows, err := app.listRules(db)
	if err != nil {
		return extension.Error(http.StatusInternalServerError, err.Error())
	}
	kind := adminURL.Query().Get("kind")
	filtered := rows
	if kind != "" {
		filtered = nil
		for _, row := range rows {
			if row.Kind == kind {
				filtered = append(filtered, row)
			}
		}
	}
	return app.render("firewall/admin_rules.html", map[string]any{
		"Title":     "Rules",
		"Subtitle":  "Enable or disable CRS files, remove rule IDs, and add custom directives.",
		"BasePath":  basePath,
		"Rows":      filtered,
		"Kind":      kind,
		"Notice":    notice,
		"Error":     errMsg,
		"CanManage": canManage,
		"CSRFField": csrf,
	})
}

func (app *firewallApp) editRule(db *gorm.DB, basePath string, id uint, errMsg string, csrf template.HTML) extension.WireResponse {
	var row ruleRow
	if err := db.Table(app.rulesTable).Where("rule_id = ?", id).First(&row).Error; err != nil {
		return extension.Error(http.StatusNotFound, "rule not found")
	}
	return app.renderRuleForm(basePath, row, false, errMsg, csrf)
}

func (app *firewallApp) renderRuleForm(basePath string, row ruleRow, isNew bool, errMsg string, csrf template.HTML) extension.WireResponse {
	title := "Edit Rule"
	action := fmt.Sprintf("%s/rules/%d", basePath, row.ID)
	if isNew {
		title = "Add Rule"
		action = basePath + "/rules/new"
	}
	return app.render("firewall/admin_rule_form.html", map[string]any{
		"Title":     title,
		"Subtitle":  "Custom SecRule directives or a SecRuleRemoveById override.",
		"BasePath":  basePath,
		"ActionURL": action,
		"CancelURL": basePath + "/rules",
		"Row":       row,
		"IsNew":     isNew,
		"Error":     errMsg,
		"CSRFField": csrf,
		"Kinds":     []string{ruleKindCustom, ruleKindRemoveID},
	})
}

func (app *firewallApp) saveRule(db *gorm.DB, body, basePath string, id uint, csrf template.HTML) extension.WireResponse {
	values, err := formValues(body)
	if err != nil {
		return app.renderRuleForm(basePath, ruleRow{}, id == 0, "invalid form", csrf)
	}
	kind := strings.TrimSpace(values.Get("kind"))
	key := strings.TrimSpace(values.Get("key"))
	title := strings.TrimSpace(values.Get("title"))
	directives := strings.TrimSpace(values.Get("directives"))
	enabled := values.Get("enabled") == "1" || values.Get("enabled") == "on"
	if kind != ruleKindCustom && kind != ruleKindRemoveID {
		return app.renderRuleForm(basePath, ruleRow{Kind: kind, Key: key, Title: title, Directives: directives, Enabled: enabled}, id == 0, "kind must be custom or remove_id", csrf)
	}
	if kind == ruleKindRemoveID {
		if _, err := strconv.Atoi(key); err != nil {
			return app.renderRuleForm(basePath, ruleRow{Kind: kind, Key: key, Title: title, Enabled: enabled}, id == 0, "remove_id key must be a numeric rule id", csrf)
		}
		if title == "" {
			title = "Disable rule " + key
		}
	}
	if kind == ruleKindCustom {
		if key == "" {
			key = "custom-" + strconv.FormatInt(time.Now().Unix(), 10)
		}
		if directives == "" {
			return app.renderRuleForm(basePath, ruleRow{Kind: kind, Key: key, Title: title, Enabled: enabled}, id == 0, "directives are required for custom rules", csrf)
		}
		if title == "" {
			title = key
		}
	}
	row := ruleRow{
		ID:         id,
		Kind:       kind,
		Key:        key,
		Title:      title,
		Directives: directives,
		Enabled:    enabled,
		Source:     "custom",
		UpdatedAt:  time.Now().UTC(),
		CreatedAt:  time.Now().UTC(),
	}
	if id != 0 {
		var existing ruleRow
		if err := db.Table(app.rulesTable).Where("rule_id = ?", id).First(&existing).Error; err != nil {
			return extension.Error(http.StatusNotFound, "rule not found")
		}
		if existing.Kind == ruleKindFile {
			return extension.Error(http.StatusBadRequest, "edit CRS files via enable/disable; delete is allowed only for custom overrides")
		}
		row.CreatedAt = existing.CreatedAt
		row.Sort = existing.Sort
	}
	if err := db.Table(app.rulesTable).Save(&row).Error; err != nil {
		return app.renderRuleForm(basePath, row, id == 0, err.Error(), csrf)
	}
	if err := app.rebuildEngine(); err != nil {
		return extension.Redirect(http.StatusSeeOther, basePath+"/rules?error="+url.QueryEscape(err.Error()))
	}
	return extension.Redirect(http.StatusSeeOther, basePath+"/rules?notice="+url.QueryEscape("Rule saved."))
}

func (app *firewallApp) listEventsAdmin(db *gorm.DB, adminURL *url.URL, basePath, notice, errMsg string, csrf template.HTML, canManage bool) extension.WireResponse {
	page := parsePage(adminURL)
	var total int64
	_ = db.Table(app.eventsTable).Count(&total).Error
	var rows []eventRow
	_ = db.Table(app.eventsTable).Order("event_id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&rows).Error
	cfg, _ := app.loadSettings()
	retention := "kept forever"
	if cfg.EventRetentionDays > 0 {
		retention = fmt.Sprintf("auto-delete after %d day(s)", cfg.EventRetentionDays)
	}
	return app.render("firewall/admin_events.html", map[string]any{
		"Title":     "Events",
		"Subtitle":  "Recent blocks, passthru detections, and ban hits. Retention: " + retention + ".",
		"BasePath":  basePath,
		"Rows":      rows,
		"Page":      page,
		"PageSize":  pageSize,
		"Total":     total,
		"Notice":    notice,
		"Error":     errMsg,
		"CanManage": canManage,
		"CSRFField": csrf,
	})
}

func (app *firewallApp) listBansAdmin(db *gorm.DB, basePath, notice string, csrf template.HTML, canManage bool) extension.WireResponse {
	rows, _ := app.listActiveBans(db)
	return app.render("firewall/admin_bans.html", map[string]any{
		"Title":     "IP Bans",
		"Subtitle":  "Temporary client bans after enforce-mode blocks.",
		"BasePath":  basePath,
		"Rows":      rows,
		"Notice":    notice,
		"CanManage": canManage,
		"CSRFField": csrf,
	})
}

func adminCanView(req extension.WireRequest) bool {
	if !userHasPermissions(req) {
		return true
	}
	return extension.UserCan(req, "firewall.view") || extension.UserCan(req, "firewall.manage")
}

func adminCanManage(req extension.WireRequest) bool {
	if !userHasPermissions(req) {
		return true
	}
	return extension.UserCan(req, "firewall.manage")
}

func userHasPermissions(req extension.WireRequest) bool {
	if req.User == nil {
		return false
	}
	_, ok := req.User["permissions"]
	return ok
}
