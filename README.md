# cannon-ext-firewall-coraza-waf

Cannon extension wrapping [OWASP Coraza](https://www.coraza.io/) / [coraza](https://github.com/corazawaf/coraza) with CRS v4.

## Features

- Request middleware inspection via Cannon `HandleRequest`
- Preload latest CRS v4 rule files from `coraza-coreruleset` (REQUEST packs on by default; RESPONSE off)
- Admin enable/disable for rule files, per-ID removals, and custom directives
- Modes: `disabled`, `passthru` (log only), `enforce` (block)
- Optional IP ban timeout after enforce blocks
- **Async Ban**: sync ban-list only on the hot path; CRS in a bounded worker; ban IP for subsequent requests
- Event log and active ban list
- Dedicated on-disk WAF store (`firewall_coraza_waf.sqlite`) with in-memory bans + bulk event flush
- Negative-cache for clean (not-banned) IPs to avoid per-request SQLite reads
- Event retention / cleanup (default 30 days)
- CLI `list-bans` / `unban` for emergency unblock

## Performance notes

Every non-excluded request pays synchronous Unix-socket IPC plus Coraza/CRS evaluation. That is expensive on a small VPS with multiple sites.

- Prefer **passthru** while tuning; switch to **enforce** only after noise is under control.
- **enforce + full CRS** is suited to edge/proxy-like deployments, not “turn on and forget” on every site.
- Enable **Async Ban** when sync CRS latency is the bottleneck: the first malicious request may still reach the app; later requests from that IP hit the sync ban list.
- Default `exclude_paths` skips `/theme`, `/assets`, and common static prefixes; keep **Skip /admin** enabled.
- RESPONSE-* CRS packs are disabled by default (response body is never inspected). Re-run **Preload CRS** after upgrade to turn them off in existing site DBs.
- Clean requests skip `MatchedRules` / Coraza `ProcessLogging`.

## CLI

```bash
export CANNON_CONFIG=/path/to/sites.json
./cannon-ext-firewall-coraza-waf list-bans --site=floridarangers
./cannon-ext-firewall-coraza-waf unban --site=floridarangers --ip=1.2.3.4
./cannon-ext-firewall-coraza-waf unban --site=floridarangers --all
```

## Build

```bash
go build -o /path/to/cannon/extensions/cannon-ext-firewall-coraza-waf .
```

## Benchmark

```bash
go test -bench=BenchmarkInspectRequestCleanGET -benchmem ./...
```

## Version

`0.2.2`
