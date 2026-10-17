package main

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/corazawaf/coraza/v3"
	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/jcchavezs/mergefs"
)

type wafEngine struct {
	waf     coraza.WAF
	version string
}

func crsVersion() string {
	return crs.Version
}

func listCRSFiles() ([]string, error) {
	var files []string
	err := fs.WalkDir(crs.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		base := path.Base(p)
		if !strings.HasPrefix(base, "REQUEST-") && !strings.HasPrefix(base, "RESPONSE-") {
			return nil
		}
		if !strings.HasSuffix(base, ".conf") {
			return nil
		}
		// Walk paths may be "@owasp_crs/…" or "owasp_crs/…"
		key := p
		if !strings.HasPrefix(key, "@") {
			key = "@" + strings.TrimPrefix(key, "/")
		}
		if !strings.Contains(key, "owasp_crs/") {
			key = "@owasp_crs/" + base
		}
		files = append(files, key)
		return nil
	})
	sort.Strings(files)
	return files, err
}

func (app *firewallApp) rebuildEngine() error {
	db, err := app.db()
	if err != nil {
		return err
	}
	if err := app.migrateTables(db); err != nil {
		return err
	}
	cfg, err := app.loadSettings()
	if err != nil {
		return err
	}
	rules, err := app.listRules(db)
	if err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("Include @coraza.conf-recommended\n")
	b.WriteString("Include @crs-setup.conf.example\n")
	// Override DetectionOnly from recommended config after includes.
	b.WriteString("SecRuleEngine On\n")
	fmt.Fprintf(&b, `SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"`+"\n",
		cfg.ParanoiaLevel, cfg.ParanoiaLevel, cfg.InboundAnomalyThreshold, cfg.OutboundAnomalyThreshold)

	hasFiles := false
	for _, row := range rules {
		if row.Kind != ruleKindFile || !row.Enabled {
			continue
		}
		fmt.Fprintf(&b, "Include %s\n", row.Key)
		hasFiles = true
	}
	if !hasFiles {
		// Empty engine still valid — no CRS files loaded yet.
		b.WriteString("# no CRS rule files enabled\n")
	}

	for _, row := range rules {
		if row.Kind != ruleKindRemoveID || !row.Enabled {
			continue
		}
		fmt.Fprintf(&b, "SecRuleRemoveById %s\n", strings.TrimSpace(row.Key))
	}
	for _, row := range rules {
		if row.Kind != ruleKindCustom || !row.Enabled {
			continue
		}
		dir := strings.TrimSpace(row.Directives)
		if dir == "" {
			continue
		}
		b.WriteString(dir)
		if !strings.HasSuffix(dir, "\n") {
			b.WriteByte('\n')
		}
	}

	root := mergefs.Merge(crs.FS, corazaconf.FS)
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(root).
		WithDirectives(b.String()))
	if err != nil {
		return fmt.Errorf("build coraza waf: %w", err)
	}

	eng := &wafEngine{waf: waf, version: crsVersion()}
	app.mu.Lock()
	app.engine = eng
	app.mu.Unlock()
	return nil
}

func (app *firewallApp) currentEngine() *wafEngine {
	app.mu.RLock()
	defer app.mu.RUnlock()
	return app.engine
}

func buildTestEngine(directives string) (*wafEngine, error) {
	root := mergefs.Merge(crs.FS, corazaconf.FS)
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(root).
		WithDirectives(directives))
	if err != nil {
		return nil, err
	}
	return &wafEngine{waf: waf, version: crsVersion()}, nil
}

func (app *firewallApp) ensureEngine() (*wafEngine, error) {
	if eng := app.currentEngine(); eng != nil {
		return eng, nil
	}
	if err := app.rebuildEngine(); err != nil {
		return nil, err
	}
	eng := app.currentEngine()
	if eng == nil {
		return nil, fmt.Errorf("waf engine unavailable")
	}
	return eng, nil
}

func (app *firewallApp) preloadCRS() (int, error) {
	files, err := listCRSFiles()
	if err != nil {
		return 0, err
	}
	db, err := app.db()
	if err != nil {
		return 0, err
	}
	if err := app.migrateTables(db); err != nil {
		return 0, err
	}
	n := 0
	for i, key := range files {
		title := strings.TrimSuffix(path.Base(key), ".conf")
		row := ruleRow{
			Kind:    ruleKindFile,
			Key:     key,
			Title:   title,
			Enabled: true,
			Sort:    i + 1,
			Source:  "crs",
		}
		var existing ruleRow
		err := db.Table(app.rulesTable).Where("kind = ? AND rule_key = ?", ruleKindFile, key).First(&existing).Error
		if err == nil {
			existing.Title = row.Title
			existing.Sort = row.Sort
			existing.Source = "crs"
			// Keep Enabled as the admin left it.
			if err := db.Table(app.rulesTable).Save(&existing).Error; err != nil {
				return n, err
			}
		} else {
			if err := db.Table(app.rulesTable).Create(&row).Error; err != nil {
				return n, err
			}
		}
		n++
	}
	if err := app.rebuildEngine(); err != nil {
		return n, err
	}
	return n, nil
}
