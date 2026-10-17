package main

import (
	"strings"
	"sync/atomic"
	"time"
)

const asyncDropLogInterval = 5 * time.Second

type asyncInspectJob struct {
	Method      string
	URL         string
	Header      map[string][]string
	Body        string
	ClientIP    string
	Path        string
	Mode        string
	BanSeconds  int
	BlockStatus int
}

func (app *firewallApp) startAsyncWorkers() {
	app.asyncOnce.Do(func() {
		if app.asyncCh == nil {
			queue := defaultFirewallSettings().AsyncBanQueue
			app.settingsMu.RLock()
			if app.settingsCached && app.settingsCache.AsyncBanQueue >= 1 {
				queue = app.settingsCache.AsyncBanQueue
			}
			app.settingsMu.RUnlock()
			app.asyncCh = make(chan asyncInspectJob, queue)
		}
		// asyncWorkers < 0: tests may provide a channel without launching workers.
		if app.asyncWorkers < 0 {
			return
		}
		n := app.asyncWorkers
		if n == 0 {
			n = 2
		}
		app.asyncWorkers = n
		for i := 0; i < n; i++ {
			go app.asyncWorkerLoop()
		}
	})
}

func (app *firewallApp) enqueueAsyncInspect(job asyncInspectJob) {
	app.startAsyncWorkers()
	if app.asyncCh == nil {
		return
	}
	select {
	case app.asyncCh <- job:
		atomic.AddInt32(&app.asyncPending, 1)
	default:
		app.noteAsyncDrop(job)
	}
}

func (app *firewallApp) noteAsyncDrop(job asyncInspectJob) {
	now := time.Now().Unix()
	key := job.ClientIP
	if key == "" {
		key = "*"
	}
	if v, ok := app.asyncDropAt.Load(key); ok {
		if last, _ := v.(int64); now-last < int64(asyncDropLogInterval/time.Second) {
			return
		}
	}
	app.asyncDropAt.Store(key, now)
	app.logEvent(eventRow{
		Action:   "async_drop",
		Mode:     job.Mode,
		Method:   job.Method,
		Path:     job.Path,
		ClientIP: job.ClientIP,
		Status:   job.BlockStatus,
		Messages: "async inspect queue full; dropped newest job",
	})
}

func (app *firewallApp) asyncWorkerLoop() {
	for job := range app.asyncCh {
		app.processAsyncInspect(job)
		atomic.AddInt32(&app.asyncPending, -1)
	}
}

func (app *firewallApp) processAsyncInspect(job asyncInspectJob) {
	eng, err := app.ensureEngine()
	if err != nil || eng == nil {
		return
	}
	result := inspectRequest(eng, job.Method, job.URL, job.Header, job.Body, job.ClientIP)
	if !result.Interrupted {
		return
	}

	msg := strings.Join(result.Messages, "; ")
	ruleCSV := joinInts(result.RuleIDs)
	action := "would_block"
	if job.BanSeconds > 0 {
		action = "async_ban"
		app.banIP(job.ClientIP, msg, job.BanSeconds)
	}
	app.logEvent(eventRow{
		Action:   action,
		Mode:     job.Mode,
		Method:   job.Method,
		Path:     job.Path,
		ClientIP: job.ClientIP,
		Status:   firstPositive(result.Status, job.BlockStatus),
		RuleIDs:  ruleCSV,
		Messages: msg,
	})
}

// waitAsyncIdle waits until accepted async jobs have finished (tests).
func (app *firewallApp) waitAsyncIdle(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&app.asyncPending) == 0 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func copyHeaderMap(h map[string][]string) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for k, vals := range h {
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[k] = cp
	}
	return out
}
