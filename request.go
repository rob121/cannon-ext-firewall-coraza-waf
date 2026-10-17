package main

import (
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rob121/cannon/extension"
)

type inspectResult struct {
	Interrupted bool
	Status      int
	Action      string
	RuleIDs     []int
	Messages    []string
}

func (app *firewallApp) handleRequest(req extension.WireRequest) extension.WireResponse {
	cfg, err := app.loadSettings()
	if err != nil {
		// Fail open if settings cannot load.
		return extension.OK()
	}
	if cfg.Mode == "disabled" {
		return extension.OK()
	}

	path := requestPath(req.URL)
	if shouldSkipPath(cfg, path) {
		return extension.OK()
	}

	clientIP := clientIPFromRequest(req)
	if banned, until := app.isBanned(clientIP); banned {
		app.logEvent(eventRow{
			Action:   "banned",
			Mode:     cfg.Mode,
			Method:   req.Method,
			Path:     path,
			ClientIP: clientIP,
			Status:   cfg.BlockStatus,
			Messages: "IP ban active until " + until.Format(timeRFC3339),
		})
		if cfg.Mode == "passthru" {
			return extension.OK()
		}
		return app.blockResponse(cfg, "Your IP is temporarily banned.")
	}

	eng, err := app.ensureEngine()
	if err != nil || eng == nil {
		return extension.OK()
	}

	body := req.Body
	if cfg.MaxBodyBytes > 0 && len(body) > cfg.MaxBodyBytes {
		body = body[:cfg.MaxBodyBytes]
	}

	result := inspectRequest(eng, req.Method, req.URL, req.Header, body, clientIP)
	if !result.Interrupted {
		return extension.OK()
	}

	ruleCSV := joinInts(result.RuleIDs)
	msg := strings.Join(result.Messages, "; ")
	action := "would_block"
	if cfg.Mode == "enforce" {
		action = "blocked"
	}
	app.logEvent(eventRow{
		Action:   action,
		Mode:     cfg.Mode,
		Method:   req.Method,
		Path:     path,
		ClientIP: clientIP,
		Status:   firstPositive(result.Status, cfg.BlockStatus),
		RuleIDs:  ruleCSV,
		Messages: msg,
	})

	if cfg.Mode == "passthru" {
		return extension.OK()
	}

	if cfg.BanSeconds > 0 {
		app.banIP(clientIP, msg, cfg.BanSeconds)
	}
	return app.blockResponse(cfg, cfg.BlockMessage)
}

func (app *firewallApp) blockResponse(cfg firewallSettings, message string) extension.WireResponse {
	status := cfg.BlockStatus
	if status < 400 {
		status = http.StatusForbidden
	}
	msg := html.EscapeString(strings.TrimSpace(message))
	if msg == "" {
		msg = "Request blocked."
	}
	body := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%d Blocked</title>
<style>
  body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;min-height:100vh;display:grid;place-items:center}
  .card{max-width:32rem;padding:2rem;border:1px solid #334155;border-radius:1rem;background:#1e293b;box-shadow:0 20px 40px rgba(0,0,0,.35)}
  h1{margin:0 0 .75rem;font-size:1.5rem}
  p{margin:0;line-height:1.55;color:#cbd5e1}
  .code{margin-top:1.25rem;font-size:.85rem;color:#94a3b8}
</style>
</head>
<body>
  <div class="card">
    <h1>Request blocked</h1>
    <p>%s</p>
  </div>
</body>
</html>`, status, msg)
	return extension.WireResponse{
		StatusCode: status,
		Header: map[string][]string{
			"Content-Type": {"text/html; charset=utf-8"},
		},
		Body: body,
		Stop: true,
	}
}

func inspectRequest(eng *wafEngine, method, rawURL string, header map[string][]string, body, clientIP string) inspectResult {
	tx := eng.waf.NewTransaction()
	defer tx.Close()

	if clientIP == "" {
		clientIP = "0.0.0.0"
	}
	tx.ProcessConnection(clientIP, 0, "0.0.0.0", 0)

	uri := rawURL
	if u, err := url.Parse(rawURL); err == nil {
		if u.RequestURI() != "" {
			uri = u.RequestURI()
		} else if u.Path != "" {
			uri = u.Path
			if u.RawQuery != "" {
				uri += "?" + u.RawQuery
			}
		}
		if host := u.Hostname(); host != "" {
			tx.AddRequestHeader("Host", host)
		}
	}
	if method == "" {
		method = http.MethodGet
	}
	tx.ProcessURI(uri, method, "HTTP/1.1")

	hasHost := false
	for k, vals := range header {
		if strings.EqualFold(k, "Host") {
			hasHost = true
		}
		for _, v := range vals {
			tx.AddRequestHeader(k, v)
		}
	}
	if !hasHost {
		tx.AddRequestHeader("Host", "localhost")
	}

	it := tx.ProcessRequestHeaders()
	if it == nil {
		if len(body) > 0 {
			if early, _, err := tx.WriteRequestBody([]byte(body)); err == nil && early != nil {
				it = early
			}
		}
		if it == nil {
			var err error
			it, err = tx.ProcessRequestBody()
			_ = err
		}
	}

	out := inspectResult{}
	if it == nil {
		// Clean request: skip MatchedRules walk and ProcessLogging (audit unused).
		return out
	}
	out.Interrupted = true
	out.Status = it.Status
	out.Action = fmt.Sprint(it.Action)

	seen := map[int]struct{}{}
	for _, mr := range tx.MatchedRules() {
		id := mr.Rule().ID()
		if id <= 0 {
			continue
		}
		// Skip our tuning SecAction and CRS init noise for the summary.
		if id >= 900000 && id < 910000 {
			continue
		}
		msg := strings.TrimSpace(mr.Message())
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out.RuleIDs = append(out.RuleIDs, id)
		if msg != "" {
			out.Messages = append(out.Messages, fmt.Sprintf("%d: %s", id, msg))
		}
	}
	return out
}

func shouldSkipPath(cfg firewallSettings, path string) bool {
	if path == "" {
		return false
	}
	if cfg.ExcludeAdmin && (path == "/admin" || strings.HasPrefix(path, "/admin/")) {
		return true
	}
	for _, prefix := range cfg.excludePathList() {
		if prefix == "" {
			continue
		}
		if path == prefix || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func requestPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

func clientIPFromRequest(req extension.WireRequest) string {
	for _, key := range []string{"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"} {
		for hk, vals := range req.Header {
			if !strings.EqualFold(hk, key) {
				continue
			}
			if len(vals) == 0 {
				continue
			}
			part := strings.TrimSpace(strings.Split(vals[0], ",")[0])
			if part != "" {
				return stripPort(part)
			}
		}
	}
	return "0.0.0.0"
}

func stripPort(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

func joinInts(ids []int) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	return strings.Join(parts, ",")
}

func firstPositive(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

const timeRFC3339 = "2006-01-02 15:04:05 MST"
