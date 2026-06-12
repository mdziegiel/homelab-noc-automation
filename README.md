# Hermes Agent Setup for MRDTech

This repository documents the MRDTech Hermes Agent control node: how it is installed, configured, secured, operated, and extended for homelab infrastructure automation.

Hermes runs on the dedicated Hermes VM and acts as the operational agent for MRDTech. It manages monitoring scripts, scheduled jobs, GitHub workflows, Portainer deployments, Wazuh checks, CrowdSec reporting, Proxmox/PBS visibility, NOC dashboard generation, and day-to-day infrastructure automation.

This is not a generic chatbot setup. It is the control plane. Treat it accordingly.

## Current MRDTech layout

| Component | Value |
|---|---|
| Hermes VM | VM 108 |
| Hermes host | `10.10.10.234` |
| Owner | Michael Dziegiel / MRDTech |
| Primary config path | `~/.hermes/config.yaml` |
| Secret env path | `~/.hermes/.env` |
| Scripts path | `~/.hermes/scripts/` |
| Skills path | `~/.hermes/skills/` |
| Logs path | `~/.hermes/logs/` |
| Session database | `~/.hermes/state.db` |

Core infrastructure Hermes knows how to operate:

- Proxmox node and PBS
- Docker/Portainer hosts
- Wazuh SIEM
- CrowdSec
- AdGuard Home and Unbound
- UniFi UDM-SE
- Uptime Kuma
- URBackup
- NOC dashboards
- GitHub repositories under `mdziegiel`

## Repository contents

```text
.
├── README.md                         # This setup and operations guide
├── .env.template                     # Sanitized environment-variable template
├── scripts/                          # Monitoring, reporting, dashboard, and watchdog scripts
├── dashboard/                        # Static NOC dashboard service notes
├── docs/                             # Architecture and setup notes
└── wazuh/                            # Wazuh rules, active-response scripts, and agent notes
```

The scripts are designed to be copied or synchronized into `~/.hermes/scripts/` and run by Hermes cron jobs or manually during incident response.

## Install Hermes Agent

Run this on the Hermes VM as `michaeld`:

```bash
curl -fsSL https://raw.githubusercontent.com/NousResearch/hermes-agent/main/scripts/install.sh | bash
```

Start the CLI:

```bash
hermes
```

Run the setup wizard if the install is new:

```bash
hermes setup
```

Health-check the installation:

```bash
hermes doctor
hermes status --all
```

## Configure model and provider

Use the interactive picker:

```bash
hermes model
```

Or set values directly:

```bash
hermes config set model.provider openai-api
hermes config set model.default gpt-5.5
```

Exact provider names and model names depend on the active Hermes build and configured credentials. Do not commit provider API keys. They belong in `~/.hermes/.env` or Hermes auth storage.

## Configure secrets

Copy the template and lock permissions:

```bash
mkdir -p ~/.hermes
cp .env.template ~/.hermes/.env
chmod 600 ~/.hermes/.env
$EDITOR ~/.hermes/.env
```

The `.env` file is the source for infrastructure credentials used by scripts and tools. It should contain values for services such as:

- `PROXMOX_URL`, `PROXMOX_TOKEN_ID`, `PROXMOX_TOKEN_SECRET`
- `PBS_PASSWORD`
- `WAZUH_URL`, `WAZUH_USERNAME`, `WAZUH_PASSWORD`
- `CROWDSEC_API_KEY`, `CROWDSEC_MACHINE_PASS`
- `UNIFI_PASSWORD`
- `ADGUARD_PASSWORD`
- `UPTIME_KUMA_URL`, `UPTIME_KUMA_API_KEY`
- `URBACKUP_URL`, `URBACKUP_USERNAME`, `URBACKUP_PASSWORD`
- `PORTAINER_URL`, `PORTAINER_USERNAME`, `PORTAINER_PASSWORD`
- Telegram/Gotify notification credentials if alerting is enabled

Never print secrets into chat, logs, commits, tickets, or README examples. Satan already has enough plaintext credentials.

## Core Hermes configuration

View config:

```bash
hermes config
```

Edit config:

```bash
hermes config edit
```

Useful settings:

```bash
hermes config set memory.memory_enabled true
hermes config set memory.user_profile_enabled true
hermes config set security.redact_secrets true
hermes config set approvals.mode manual
hermes config set agent.max_turns 90
```

Use `manual` approvals for normal operations. Use `smart` only if you trust the environment. Use `off` only when you deliberately want the guardrails removed and are prepared to own the crater.

## Toolsets

Inspect enabled toolsets:

```bash
hermes tools list
```

Interactive tool configuration:

```bash
hermes tools
```

Typical MRDTech control-node toolsets:

- terminal
- file
- web/search
- browser when needed
- skills
- memory
- session_search
- cronjob
- delegation
- messaging if gateway delivery is configured
- homeassistant if smart-home control is required

Tool changes take effect on a new Hermes session.

## Skills

List skills:

```bash
hermes skills list
```

Install or update skills:

```bash
hermes skills browse
hermes skills install <skill-id>
hermes skills check
hermes skills update
```

MRDTech-specific operational skills should live under `~/.hermes/skills/` and document workflows that are too specific or too easy to forget, such as:

- Portainer stack management
- MRDTech infrastructure monitoring
- CrowdSec/NPM log ingestion
- SSH key bootstrap and rotation
- YAML-configurable dashboard deployment
- Home Assistant operations
- GitHub workflows

Good skills include triggers, exact commands, pitfalls, and verification steps. Bad skills are vibes with YAML frontmatter.

## Scripts installation

Install scripts into Hermes:

```bash
mkdir -p ~/.hermes/scripts
rsync -av scripts/ ~/.hermes/scripts/
chmod +x ~/.hermes/scripts/*.py
```

Run a script manually:

```bash
python3 ~/.hermes/scripts/report_uptime_kuma.py
python3 ~/.hermes/scripts/report_wazuh_alerts.py
python3 ~/.hermes/scripts/generate_dashboard.py
```

Scripts should be quiet when there is nothing to report. Cron jobs should not spam. Alert fatigue is how monitoring becomes wallpaper.

## Cron jobs

List jobs:

```bash
hermes cron list
```

Create script-only watchdog jobs:

```bash
hermes cron create 'every 15m' \
  --name docker-watchdog \
  --script alert_docker_watchdog.py \
  --no-agent
```

Create LLM-assisted report jobs only when summarization or reasoning is actually useful:

```bash
hermes cron create '0 8 * * *' \
  --name morning-infra-briefing \
  --prompt 'Generate a concise MRDTech infrastructure briefing from current monitoring data.'
```

Use script-only jobs for threshold alerts, heartbeat checks, and deterministic reports. Use agent jobs for summarization, correlation, and triage.

## Gateway setup

Configure messaging platforms:

```bash
hermes gateway setup
```

Install gateway as a user service:

```bash
printf 'y\ny\n' | hermes gateway install --force
```

Verify:

```bash
hermes gateway status
systemctl --user is-active hermes-gateway
journalctl --user -u hermes-gateway -n 50 --no-pager
```

Restart after config changes:

```bash
hermes gateway restart
```

Gateway platform blocks in `config.yaml` are not enough. A platform is not enabled until it has valid credentials or pairing configured.

## GitHub setup

Set git identity:

```bash
git config --global user.name "Michael Dziegiel"
git config --global user.email "mdziegiel74@yahoo.com"
```

Verify GitHub CLI or SSH access:

```bash
gh auth status || true
ssh -T git@github.com
```

Common MRDTech pattern:

```bash
cd /home/michaeld/github/<repo>
git status --short --branch
python3 -m unittest discover -s tests -v || true
git add -A
git commit -m "type: concise message"
git push
```

SSH can push to existing repositories. Repository creation may require GitHub web/API credentials.

## Portainer deployment pattern

Use the Portainer API rather than random SSH rituals when Portainer is the available control path.

Discovery:

```bash
# Authenticate against the correct Portainer instance, then:
GET /api/endpoints
GET /api/stacks
```

For local-image app deployments:

1. Build a tar context from the project root.
2. Send it to Portainer Docker API proxy:
   `POST /api/endpoints/<endpoint_id>/docker/build?t=<image>:<tag>&rm=1`
3. Stop/remove the previous container with the same name.
4. Recreate it with preserved or explicit configuration:
   - published port
   - restart policy
   - named data volumes
   - read-only host binds
   - required environment variables
   - healthcheck
5. Start and poll container state until running/healthy.
6. Verify the app over the host IP and published port.

For backup-verification workloads, backup mounts must be read-only:

```text
/mnt/qnap-backups/urbackup:/mnt/qnap-backups/urbackup:ro
```

A container that can write to backup storage is not a verifier. It is a liability with a web UI.

## NOC dashboard

Generate manually:

```bash
python3 ~/.hermes/scripts/generate_dashboard.py
```

The dashboard is static HTML generated from live service collectors. One failed collector should degrade one card, not the entire page.

See:

- `dashboard/README.md`
- `docs/architecture.md`
- `docs/setup.md`

## Wazuh integration

Wazuh files in this repo include:

- `wazuh/ossec.conf.additions.xml`
- `wazuh/local_rules.xml`
- `wazuh/custom-telegram.py`
- `wazuh/windows-agent-sysmon.xml`

Apply Wazuh changes surgically. Validate XML before restart. Restarting Wazuh blindly is how logs become archaeology.

Suggested checks:

```bash
xmllint --noout wazuh/local_rules.xml
xmllint --noout wazuh/ossec.conf.additions.xml
```

Deployment to Wazuh manager requires appropriate host access and privilege. Do not bypass access controls from Hermes.

## Backup verification operations

Backup verification should prove backup data can be read, not merely that a backup service is reachable.

Expected checks:

- API metadata where available
- independent backup-directory discovery
- newest backup selection
- critical path presence
- random file readability
- checksum manifest validation when present
- image metadata/readability checks when tools are available
- stable JSON output for dashboards/NOC ingestion

Backups must be mounted read-only. Verification history should persist in a data volume.

## Security rules

- Secrets live in `~/.hermes/.env`, not Git.
- Keep `security.redact_secrets` enabled.
- Prefer read-only mounts for monitoring and verification.
- Do not expose dashboards, APIs, or agent gateways directly to the public internet.
- Use Tailscale/VPN/Cloudflare Zero Trust where remote access is needed.
- Verify every deployment with real app-layer checks.
- If credentials are missing or invalid, stop and report that. Do not hallucinate success. Nietzsche would consider that beneath even humans.

## Routine verification checklist

After setup or major changes:

```bash
hermes doctor
hermes status --all
hermes tools list
hermes skills list
hermes cron list
hermes gateway status
python3 ~/.hermes/scripts/generate_dashboard.py
```

For repository updates:

```bash
git status --short --branch
git log --oneline -5
git remote -v
```

For deployed apps:

```bash
curl -fsS http://<host>:<port>/api/health
```

Also verify container state through Portainer or Docker. HTTP health alone can lie. Containers also lie. Cross-check both.

## Recovery notes

If Hermes behaves strangely:

```bash
hermes doctor --fix
hermes config check
hermes gateway restart
journalctl --user -u hermes-gateway -n 100 --no-pager
```

If a tool or skill change does not appear, start a new Hermes session. Tool and skill context is cached for prompt stability.

If a cron job is noisy, fix the script output. Empty stdout should mean silence for script-only watchdogs.

## License

MIT. Use it correctly or don't use it.
