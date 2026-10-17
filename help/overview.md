# Coraza WAF

[OWASP Coraza](https://www.coraza.io/) request firewall for Cannon, with the latest [OWASP CRS v4](https://github.com/corazawaf/coraza-coreruleset) rule pack.

## Modes

| Mode | Behavior |
|------|----------|
| `disabled` | No inspection |
| `passthru` | Inspect and log `would_block` events, but never stop the request |
| `enforce` | Block interrupted requests (default HTTP 403) and optionally ban the client IP |

Configure mode, ban duration, anomaly thresholds, paranoia level, path exclusions, and event retention under **Firewall Settings**.

## Setup

1. Activate the extension for the site.
2. Open **Firewall** in the admin menu.
3. Click **Preload CRS** to import CRS rule files.
4. Leave mode on **passthru** and watch **Events**.
5. Disable noisy files or add `remove_id` overrides, then switch to **enforce**.

`/admin` is skipped by default so you cannot lock yourself out of the control panel. Unban IPs under **Firewall → Bans**, or from the command line (see below).

## Unban (admin and CLI)

Admin: **Firewall → Bans → Unban**.

CLI (requires `CANNON_CONFIG` pointing at `sites.json`, same as a running Cannon install):

```bash
cannon-ext-firewall-coraza-waf list-bans --site=floridarangers
cannon-ext-firewall-coraza-waf unban --site=floridarangers --ip=1.2.3.4
cannon-ext-firewall-coraza-waf unban --site=floridarangers --all
```

Deleting a ban row (CLI or SQL) takes effect on the next request without restarting the extension.

## Rule management

- **CRS files** — enable/disable whole `@owasp_crs/*.conf` packs
- **remove_id** — `SecRuleRemoveById` for a specific CRS rule ID
- **custom** — additional ModSecurity-compatible directives

After rule or settings changes the engine rebuilds automatically (or use **Rebuild Engine**).

## Events retention

Events are stored in `firewall_coraza_waf_events`. **Event Retention (days)** (default `30`, `0` = keep forever) deletes older rows on an hourly background pass and opportunistically after new events. Expired IP bans are always removed. Use **Run cleanup now** on the Events page to purge immediately.

## Request pipeline

The extension registers Cannon `HandleRequest` middleware. It runs early in the site HTTP chain, processes method/URI/headers/body with Coraza, and either continues or returns a blocked HTML response with `stop: true`.
