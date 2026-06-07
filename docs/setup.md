# Setup — Replicate From Scratch

This guide builds the monitoring/automation layer from nothing. It assumes you
already have a Proxmox host and the services you want to monitor (or a subset —
every collector degrades gracefully if a service is absent).

All IPs below are sanitized `10.0.0.x` placeholders. Use your real subnet.

---

## 0. Prerequisites

- A Linux control node (VM or LXC) with Python 3.8+ and LAN access to your
  services. The stack is **stdlib-only** — no `pip` required.
- Read-only API credentials for each service you want to monitor.
- A Telegram bot (via [@BotFather](https://t.me/botfather)) and your chat id.
- Optional: a [Gotify](https://gotify.net/) server for out-of-band alerts.

---

## 1. Lay down the files

```bash
git clone https://github.com/YOUR_GITHUB_USER/homelab-monitoring.git
cd homelab-monitoring

mkdir -p ~/.hermes/scripts
cp scripts/*.py ~/.hermes/scripts/
```

## 2. Configure credentials

```bash
cp .env.template ~/.hermes/.env
chmod 600 ~/.hermes/.env
$EDITOR ~/.hermes/.env
```

Fill in every `YOUR_X_HERE` placeholder for the services you run. Leave unused
ones blank — their cards/scripts will simply report "not configured" instead of
failing. **Tips for least-privilege credentials:**

- **Proxmox** — create an API token (`Datacenter → Permissions → API Tokens`)
  with `PVEAuditor` role. Never use the root password.
- **Wazuh indexer** — create a dedicated read-only role scoped to
  `wazuh-alerts-*` and a user mapped to it; do not use `admin`. Example via the
  OpenSearch Security API:
  ```bash
  # role: read-only on wazuh-alerts-* only
  curl -sk -u admin:PASS -X PUT https://10.0.0.233:9200/_plugins/_security/api/roles/alerts_ro \
    -H 'Content-Type: application/json' -d '{
      "cluster_permissions":["cluster_composite_ops_ro"],
      "index_permissions":[{"index_patterns":["wazuh-alerts-*"],"allowed_actions":["read"]}]}'
  # user + mapping omitted for brevity — see wazuh/README.md
  ```
- **Cloudflare** — scoped API token with Analytics + Firewall **read** only.
- **UniFi** — a local-only admin account (API auth doesn't support 2FA accounts).

## 3. Verify connectivity

```bash
python3 ~/.hermes/scripts/generate_dashboard.py
```

This polls everything and writes `~/homelab-dashboard/index.html`. The console
output reports how many sources came back green and lists any errors. Fix
credentials until you're happy, then:

```bash
cd ~/homelab-dashboard && python3 -m http.server 8080
# browse http://YOUR_CONTROL_NODE_IP:8080  (over VPN/Tailscale only)
```

## 4. Schedule the monitors

Two options.

### Option A — cron
```cron
# Dashboard + watchdogs
*/15 * * * *  /usr/bin/python3 $HOME/.hermes/scripts/generate_dashboard.py
*/15 * * * *  /usr/bin/python3 $HOME/.hermes/scripts/alert_docker_watchdog.py
0 * * * *     /usr/bin/python3 $HOME/.hermes/scripts/alert_new_device.py
0 */2 * * *   /usr/bin/python3 $HOME/.hermes/scripts/alert_vm_health.py
0 */6 * * *   /usr/bin/python3 $HOME/.hermes/scripts/alert_disk_space.py
# Daily digests (20:00 / 08:00 / 08:30 / 09:00)
0 20 * * *    /usr/bin/python3 $HOME/.hermes/scripts/report_wazuh_alerts.py
0 20 * * *    /usr/bin/python3 $HOME/.hermes/scripts/report_crowdsec.py
0 20 * * *    /usr/bin/python3 $HOME/.hermes/scripts/report_adguard.py
0 20 * * *    /usr/bin/python3 $HOME/.hermes/scripts/report_unifi_threats.py
0 20 * * *    /usr/bin/python3 $HOME/.hermes/scripts/report_uptime_kuma.py
0 8 * * *     /usr/bin/python3 $HOME/.hermes/scripts/report_pbs_backups.py
0 8 * * *     /usr/bin/python3 $HOME/.hermes/scripts/report_urbackup.py
30 8 * * *    /usr/bin/python3 $HOME/.hermes/scripts/alert_cert_expiry.py
0 9 * * *     /usr/bin/python3 $HOME/.hermes/scripts/alert_tailscale_key_expiry.py
# Weekly
0 9 * * 1     /usr/bin/python3 $HOME/.hermes/scripts/telegram_heartbeat.py
0 11 * * 6    /usr/bin/python3 $HOME/.hermes/scripts/morning_briefing.py
0 12 * * 6    /usr/bin/python3 $HOME/.hermes/scripts/report_weekly.py
```

> The alert scripts are **stateful** — they only message you on a state change
> (e.g. a VM dropping), staying silent otherwise. Digests run on a fixed cadence.

### Option B — systemd timers
Use `dashboard/homelab-dashboard.service` as a template `oneshot` unit and pair
it with a `.timer`. Repeat per script, or wrap them in a single dispatcher.

## 5. Notification delivery

Scripts deliver via `notify.py`, which writes stdout (Telegram path) and mirrors
non-empty output to Gotify. Set `TELEGRAM_BOT_TOKEN` + `TELEGRAM_HOME_CHANNEL`
and optionally `GOTIFY_URL` + `GOTIFY_TOKEN` in `.env`.

> **DNS gotcha:** if you run AdGuard/Pi-hole, make sure `api.telegram.org` isn't
> being blocked — some blocklists sinkhole it to `0.0.0.0`, which silently kills
> alert delivery. Allowlist it: `@@||api.telegram.org^`. The weekly
> `telegram_heartbeat.py` exists to catch exactly this failure and shouts via
> Gotify if Telegram is unreachable.

## 6. Apply Wazuh hardening (optional but recommended)

See **[../wazuh/README.md](../wazuh/README.md)** for the active-response,
brute-force rule 100100, Telegram integration, and the low-noise Sysmon ruleset.

Always validate before restarting the manager:
```bash
printf 'test\n' | sudo /var/ossec/bin/wazuh-logtest    # ruleset must compile clean
sudo systemctl restart wazuh-manager
```
Ideally restart behind a rollback guard that restores the previous config and
restarts again if the manager fails to come up — a malformed rules/decoder file
will refuse to start `wazuh-analysisd`.

## 7. Harden the control node

- `chmod 600 ~/.hermes/.env` — it holds read creds to your whole lab.
- SSH key-only, no password auth.
- Never expose the dashboard or any API to the internet. Tailscale/VPN only.
- Rotate any credential that has ever appeared in plaintext (logs, chat, etc.).
