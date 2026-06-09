# generate_dashboard.py changelog

## 2026-06-09 dashboard consolidation
- Canonical generator confirmed as `/home/michaeld/.hermes/scripts/generate_dashboard.py`.
- Served output confirmed as `/home/michaeld/mrdtech-dashboard/index.html`, served by `mrdtech-dashboard.service` on port 8080.
- Consolidated duplicate repo dashboard work into the live canonical generator.
- Kept live tiles: Proxmox, Docker / Portainer, PBS Backups, Uptime Kuma, URBackup, Home Assistant, Cloudflare, Nginx Proxy Manager, CrowdSec, Wazuh SIEM, Malware Detection, UniFi UDM-SE, AdGuard DNS1/DNS2, Tailscale, WGDashboard, Plex, Tautulli, Sonarr, Radarr, SABnzbd, Overseerr, Prowlarr, QNAP cards, Proxmox storage gauges, Uptime History, TLS Cert Expiry, Active Alerts.
- Added new tiles into the live generator: SMART / Disk Health, WAN / Internet, LimaCharlie (LC).
- Relabeled malware card to `MALWARE DETECTION (WAZUH)` so it is distinct from LimaCharlie.
- Repo path `/home/michaeld/github/mrdtech-homelab/scripts/generate_dashboard.py` is symlinked to canonical generator to prevent split-brain edits.
- Backups before edits: `/home/michaeld/.hermes/scripts/generate_dashboard.py.bak-20260609-114539`, `/home/michaeld/.hermes/scripts/generate_dashboard.py.bak-20260609-115348`.
- Verification: py_compile passed; render wrote the served index; HTTP check confirmed all expected tiles.
- CrowdSec auth remains blocked: current and backup `.env` CrowdSec API/machine creds return HTTP 403/401 against LAPI. No credentials were changed.

## 2026-06-09 Wazuh card merge and layout reorder
- Backup before edit: `/home/michaeld/.hermes/scripts/generate_dashboard.py.bak-20260609-121246-wazuh-merge`.
- Merged `MALWARE DETECTION (WAZUH)` into `WAZUH SIEM` as a single card.
- Kept Wazuh agent health at the top of the card: agents online, alerts 24h, high/crit 24h.
- Kept malware source liveness/count logic at the bottom of the same card: ClamAV, YARA, VirusTotal, Defender.
- Reordered only System Status and Security & Network card order to match Michael's requested layout.
- Preserved existing collectors, data sources, liveness states, and graceful degraded/unreachable rendering.
