# cannon-ext-firewall-coraza-waf

Cannon extension wrapping [OWASP Coraza](https://www.coraza.io/) / [coraza](https://github.com/corazawaf/coraza) with CRS v4.

## Features

- Request middleware inspection via Cannon `HandleRequest`
- Preload latest CRS v4 rule files from `coraza-coreruleset`
- Admin enable/disable for rule files, per-ID removals, and custom directives
- Modes: `disabled`, `passthru` (log only), `enforce` (block)
- Optional IP ban timeout after enforce blocks
- Event log and active ban list
- Dedicated on-disk WAF store (`firewall_coraza_waf.sqlite`) with in-memory bans + bulk event flush
- Event retention / cleanup (default 30 days)
- CLI `list-bans` / `unban` for emergency unblock

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

## Version

`0.2.0`
