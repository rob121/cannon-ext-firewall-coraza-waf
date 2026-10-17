package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// inspectRequestLegacy mirrors the pre-0.2.1 hot path: always ProcessLogging
// and always walk MatchedRules, even on clean traffic.
func inspectRequestLegacy(eng *wafEngine, method, rawURL string, header map[string][]string, body, clientIP string) inspectResult {
	tx := eng.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

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
	if it != nil {
		out.Interrupted = true
		out.Status = it.Status
		out.Action = fmt.Sprint(it.Action)
	}
	seen := map[int]struct{}{}
	for _, mr := range tx.MatchedRules() {
		id := mr.Rule().ID()
		if id <= 0 {
			continue
		}
		if id >= 900000 && id < 910000 {
			continue
		}
		msg := strings.TrimSpace(mr.Message())
		if msg == "" && !out.Interrupted {
			continue
		}
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

// buildRequestOnlyEngine loads CRS REQUEST packs only (default production shape after 0.2.1).
func buildRequestOnlyEngine(b *testing.B) *wafEngine {
	b.Helper()
	files, err := listCRSFiles()
	if err != nil {
		b.Fatal(err)
	}
	var sb strings.Builder
	sb.WriteString("Include @coraza.conf-recommended\nInclude @crs-setup.conf.example\nSecRuleEngine On\n")
	sb.WriteString(`SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=1,setvar:tx.detection_paranoia_level=1,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"` + "\n")
	for _, f := range files {
		if isResponseCRSFile(f) {
			continue
		}
		sb.WriteString("Include " + f + "\n")
	}
	eng, err := buildTestEngine(sb.String())
	if err != nil {
		b.Fatal(err)
	}
	return eng
}

func buildFullCRSEngine(b *testing.B) *wafEngine {
	b.Helper()
	files, err := listCRSFiles()
	if err != nil {
		b.Fatal(err)
	}
	var sb strings.Builder
	sb.WriteString("Include @coraza.conf-recommended\nInclude @crs-setup.conf.example\nSecRuleEngine On\n")
	sb.WriteString(`SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=1,setvar:tx.detection_paranoia_level=1,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"` + "\n")
	for _, f := range files {
		sb.WriteString("Include " + f + "\n")
	}
	eng, err := buildTestEngine(sb.String())
	if err != nil {
		b.Fatal(err)
	}
	return eng
}

func BenchmarkInspectRequestCleanGET_RequestOnly(b *testing.B) {
	eng := buildRequestOnlyEngine(b)
	hdr := map[string][]string{
		"User-Agent": {"Mozilla/5.0"},
		"Host":       {"example.com"},
		"Accept":     {"text/html"},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := inspectRequest(eng, http.MethodGet, "http://example.com/", hdr, "", "203.0.113.10")
		if res.Interrupted {
			b.Fatal("clean GET should not interrupt")
		}
	}
}

func BenchmarkInspectRequestCleanGET_FullCRS(b *testing.B) {
	eng := buildFullCRSEngine(b)
	hdr := map[string][]string{
		"User-Agent": {"Mozilla/5.0"},
		"Host":       {"example.com"},
		"Accept":     {"text/html"},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := inspectRequest(eng, http.MethodGet, "http://example.com/", hdr, "", "203.0.113.10")
		if res.Interrupted {
			b.Fatal("clean GET should not interrupt")
		}
	}
}

func BenchmarkInspectRequestCleanGET_LegacyHotPath(b *testing.B) {
	eng := buildFullCRSEngine(b)
	hdr := map[string][]string{
		"User-Agent": {"Mozilla/5.0"},
		"Host":       {"example.com"},
		"Accept":     {"text/html"},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := inspectRequestLegacy(eng, http.MethodGet, "http://example.com/", hdr, "", "203.0.113.10")
		if res.Interrupted {
			b.Fatal("clean GET should not interrupt")
		}
	}
}

func mustRequestOnlyEngine(t *testing.T) *wafEngine {
	t.Helper()
	files, err := listCRSFiles()
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	sb.WriteString("Include @coraza.conf-recommended\nInclude @crs-setup.conf.example\nSecRuleEngine On\n")
	sb.WriteString(`SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=1,setvar:tx.detection_paranoia_level=1,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"` + "\n")
	resp := 0
	for _, f := range files {
		if isResponseCRSFile(f) {
			resp++
			continue
		}
		sb.WriteString("Include " + f + "\n")
	}
	if resp == 0 {
		t.Fatal("expected RESPONSE packs in CRS set")
	}
	eng, err := buildTestEngine(sb.String())
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func TestInspectCleanSkipsMatchedRulesSummary(t *testing.T) {
	eng := mustRequestOnlyEngine(t)
	res := inspectRequest(eng, http.MethodGet, "http://example.com/", map[string][]string{
		"User-Agent": {"Mozilla/5.0"},
		"Host":       {"example.com"},
	}, "", "203.0.113.10")
	if res.Interrupted {
		t.Fatal("clean GET interrupted")
	}
	if len(res.RuleIDs) != 0 || len(res.Messages) != 0 {
		t.Fatalf("clean path should not collect MatchedRules: ids=%v msgs=%v", res.RuleIDs, res.Messages)
	}
}

// TestInspectHotPathFewerAllocsThanLegacy asserts skipping MatchedRules/ProcessLogging
// on clean traffic allocates less than the pre-0.2.1 path (CRS eval still dominates wall time).
func TestInspectHotPathFewerAllocsThanLegacy(t *testing.T) {
	eng := mustRequestOnlyEngine(t)
	hdr := map[string][]string{
		"User-Agent": {"Mozilla/5.0"},
		"Host":       {"example.com"},
		"Accept":     {"text/html"},
	}
	newAllocs := testing.AllocsPerRun(40, func() {
		_ = inspectRequest(eng, http.MethodGet, "http://example.com/", hdr, "", "203.0.113.10")
	})
	oldAllocs := testing.AllocsPerRun(40, func() {
		_ = inspectRequestLegacy(eng, http.MethodGet, "http://example.com/", hdr, "", "203.0.113.10")
	})
	t.Logf("new allocs/op=%.0f legacy allocs/op=%.0f", newAllocs, oldAllocs)
	if newAllocs >= oldAllocs {
		t.Fatalf("expected fewer allocs on new hot path: new=%.0f legacy=%.0f", newAllocs, oldAllocs)
	}
}
