# Architecture

Network and compute layout for the homelab. **All IPs are sanitized placeholders**
in the `10.0.0.0/24` range — substitute your real subnet.

## Network topology

```
                          Internet (Business fiber)
                                   │
                          ┌────────▼─────────┐
                          │  Cloudflare      │  DNS · WAF · Zero Trust · Tunnels
                          └────────┬─────────┘
                                   │
                          ┌────────▼─────────┐
                          │  UniFi UDM-SE    │  10.0.0.1
                          │  routing/FW/IPS  │
                          └────────┬─────────┘
                                   │  LAN 10.0.0.0/24
        ┌──────────────┬───────────┼───────────┬──────────────┐
        │              │           │           │              │
   ┌────▼────┐   ┌─────▼────┐  ┌───▼────┐  ┌───▼─────┐   ┌────▼─────┐
   │ Proxmox │   │  QNAP ×3 │  │  PBS   │  │ Worksta-│   │ AdGuard  │
   │  node   │   │  NAS     │  │  NUC   │  │ tions   │   │ + Unbound│
   │10.0.0.251│   │          │  │10.0.0.77│  │         │   │10.0.0.21 │
   └────┬────┘   └──────────┘  └────────┘  └─────────┘   └──────────┘
        │
        │  Tailscale mesh overlays the entire LAN (MagicDNS) for remote access
        ▼
  ~12 purpose-built VMs (below)
```

## Proxmox VM layout

Hardware: multi-core i7, 64 GB RAM, Proxmox VE 9.x. Sanitized IPs.

| VMID | Name | Role | Example IP |
|------|------|------|-----------|
| 100 | casaos | CasaOS app platform | 10.0.0.x |
| 101 | docker | Docker host — production workloads (Portainer, CrowdSec, Gotify, *arr, NPM) | 10.0.0.237 |
| 102 | freshrss | RSS aggregator | 10.0.0.x |
| 103 | wazuh | Wazuh SIEM (manager + indexer + dashboard) | 10.0.0.233 |
| 104 | fing | Network discovery | 10.0.0.x |
| 105 | homeassistant | Home Assistant | 10.0.0.x |
| 106 | linkstack | Link page | 10.0.0.x |
| 107 | wireguard | WireGuard + WG-Dashboard | 10.0.0.x |
| 108 | control-node | **Agentic control node** — runs cron scripts + dashboard | 10.0.0.234 |
| 109 | unbound | Recursive DNS (DNSSEC) | 10.0.0.x |
| 110 | ubuntu-server | General-purpose | 10.0.0.x |
| — | PBS-NUC | Proxmox Backup Server (bare metal) | 10.0.0.77 |

## Storage

| Unit | Role |
|------|------|
| QNAP NAS ×3 | NFS datastores for VM disks, media, and backup targets |
| PBS-NUC | Proxmox Backup Server — dedup'd VM backups + verification |
| URBackup | Endpoint (workstation) file + image backups |

## Service → host map

| Service | Host | Port(s) | Env var |
|---------|------|---------|---------|
| Proxmox VE API | 10.0.0.251 | 8006 | `PROXMOX_HOST` |
| Proxmox Backup Server | 10.0.0.77 | 8007 | `PBS_HOST` |
| Wazuh manager API | 10.0.0.233 | 55000 | `WAZUH_HOST` |
| Wazuh indexer | 10.0.0.233 | 9200 | `WAZUH_INDEXER_HOST` |
| UniFi controller | 10.0.0.1 | 443 | `UNIFI_HOST` |
| AdGuard Home | 10.0.0.21 | 80/443 | `ADGUARD_HOST` |
| CrowdSec LAPI | 10.0.0.237 | 18080 | `DOCKER_HOST_IP` |
| Portainer | 10.0.0.237 | 9443 | `PORTAINER_URL` |
| Gotify | 10.0.0.237 | 10143 | `GOTIFY_URL` |
| Uptime Kuma | 10.0.0.237 | 3001 | `UPTIME_KUMA_URL` |
| Nginx Proxy Manager | 10.0.0.237 | 81 | `NPM_URL` |
| URBackup | 10.0.0.76 | 55414 | `URBACKUP_URL` |
| Control node / dashboard | 10.0.0.234 | 8080 | `HERMES_HOST` |

## Data flow

1. **Collection** — the control node (10.0.0.234) polls each service API over the
   LAN every cron interval. No agents are installed on the control node beyond the
   Python stdlib.
2. **Aggregation** — `generate_dashboard.py` fans out to all `collect_*()`
   functions, builds a unified state dict, and snapshots daily metrics to
   `trends.json` for sparklines.
3. **Rendering** — a static `index.html` is written and served read-only.
4. **Alerting** — stateful alert scripts compare current vs last-known state and
   push only deltas to Telegram (primary) and Gotify (out-of-band fallback).

## Trust boundaries

- The control node holds read credentials to every service — treat it as a
  high-value box. Lock down SSH, keep `.env` at `chmod 600`.
- TLS verification is disabled only for internal self-signed endpoints (LAN).
- Nothing here should be reachable from the public internet. Remote access is via
  Tailscale only.
