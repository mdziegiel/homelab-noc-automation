# Homelab NOC Dashboard

A single-file, dependency-free network operations center (NOC) dashboard for the
whole homelab. One Python script (`generate_dashboard.py`, stdlib only) polls
every service API, renders a self-contained dark-themed HTML page, and writes it
to a static file served by any web server. No framework, no database, no build
step.

![dashboard](https://img.shields.io/badge/dependencies-zero-brightgreen)
![python](https://img.shields.io/badge/python-3.8%2B-blue)

## Architecture

```
                ┌──────────────────────────────────────┐
   cron (15m)──▶│  generate_dashboard.py (stdlib only)  │
                │  ├─ load ~/.hermes/.env (hosts+creds)  │
                │  ├─ collect_*() one per service        │
                │  │    parallel-ish sequential polling  │
                │  ├─ update_trends() → trends.json      │
                │  └─ render() → static index.html       │
                └───────────────┬──────────────────────┘
                                ▼
                    ~/homelab-dashboard/index.html
                                ▼
                   http.server / nginx / caddy :8080
```

Every `collect_<service>()` function is isolated and fault-tolerant: one service
being down degrades only its card, never the whole page. Each returns a dict with
a `state` (`ok` / `warn` / `crit` / `error` / `degraded`) that drives card color.

## Cards

| Card | Source API | Key metrics |
|------|-----------|-------------|
| **Proxmox** | PVE API token | node CPU/RAM, VM up/down, storage |
| **Docker** | Portainer API | container counts, stopped/unhealthy |
| **PBS** | Proxmox Backup Server | datastore usage, last backup task status |
| **Wazuh SIEM** | manager API + indexer | agents online, alerts 24h, high/crit 24h |
| **CrowdSec** | LAPI | active bans, local bans, detections 24h, ban trend sparkline |
| **AdGuard DNS1/DNS2** | AdGuard control API | queries, block %, blocked trend sparkline |
| **UniFi** | network API | WAN status, clients, IPS events, per-SSID clients, WAN data, VPN |
| **Cloudflare** | GraphQL Analytics | requests, threats, bandwidth, WAF events 24h |
| **Uptime Kuma** | Prometheus /metrics | per-monitor up/down, cert days remaining |
| **Tailscale** | API | device count, key-expiry warnings |
| **Home Assistant** | REST API | entity/automation health |
| **NPM** | Nginx Proxy Manager API | proxy hosts, cert status |
| **Plex / Tautulli** | media APIs | streams, library |
| **QNAP / URBackup** | NAS + backup | storage, backup health |

Sparklines are inline SVG built from a rolling daily snapshot persisted in
`trends.json` (gitignored). A card needs ≥2 days of history before its sparkline
renders; until then it shows "collecting trend data…".

## Deployment

```bash
# 1. Put the generator + .env in place
cp scripts/generate_dashboard.py ~/.hermes/scripts/
cp .env.template ~/.hermes/.env && chmod 600 ~/.hermes/.env   # then fill it in

# 2. Generate once to verify
python3 ~/.hermes/scripts/generate_dashboard.py
#  → writes ~/homelab-dashboard/index.html

# 3. Serve it (simplest possible)
cd ~/homelab-dashboard && python3 -m http.server 8080
#  → http://YOUR_CONTROL_NODE_IP:8080

# 4. Regenerate on a schedule (systemd timer or cron, every 15 min)
cp dashboard/homelab-dashboard.service /etc/systemd/system/
#  pair with a .timer, or just use cron:
#  */15 * * * * /usr/bin/python3 ~/.hermes/scripts/generate_dashboard.py
```

> **Important:** editing `generate_dashboard.py` does **not** change what's served
> until you re-run it — the served page is the static `index.html`, regenerated
> only on the timer. After any edit, run the generator manually to refresh.

## Security notes

- The dashboard contains live infrastructure telemetry — **do not expose it to
  the public internet.** Keep it behind Tailscale / VPN / auth proxy.
- `generate_dashboard.py` reads credentials from `~/.hermes/.env` only. No secret
  is ever written into the generated HTML (only aggregate metrics).
- TLS verification is disabled for internal self-signed endpoints (`CERT_NONE`).
  That is acceptable for LAN-only polling; do not point it at untrusted hosts.
