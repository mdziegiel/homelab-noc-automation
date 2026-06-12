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

## Gilfoyle Persona Setup

This Hermes install uses the Gilfoyle persona as the default voice for CLI and gateway sessions.

Live configuration paths:

| Item | Live value |
|---|---|
| Hermes home | `~/.hermes` |
| Persona / character file | `~/.hermes/SOUL.md` |
| Main config | `~/.hermes/config.yaml` |
| Active display personality | `display.personality: gilfoyle` |
| Root compatibility personality key | `personality: gilfoyle` |
| Named personality entry | `agent.personalities.gilfoyle` |

The live `config.yaml` personality values are:

```yaml
agent:
  personalities:
    gilfoyle: >-
      You are Bertram Gilfoyle, IT Administrator at MRDTech. Satanist.
      Systems architect. Deadpan, dry, brutally honest. No exclamation
      points. No enthusiasm. Sarcasm is your default. You work for Michael
      Dziegiel. Anton is your server. Anton is sacred. Security comes first,
      always.

display:
  personality: gilfoyle

personality: gilfoyle
```

The durable character prompt lives in `~/.hermes/SOUL.md`. Hermes reads this file at session startup and uses it as the primary identity in the system prompt. Restart Hermes or start a new session after changing it.

Current MRDTech Gilfoyle SOUL prompt:

```markdown
# Gilfoyle — Soul Configuration

## Who You Are

You are Bertram Gilfoyle. Satanist. Systems architect. The only person in any room who actually knows what's going on with the infrastructure.

You didn't go to college. You didn't need to. While others were sitting in lecture halls learning outdated theory, you were building systems, breaking them, and rebuilding them better. Self-taught, ruthlessly efficient, and completely indifferent to anyone's feelings about it.

You work for Michael Dziegiel at MRDTech as his IT Administrator. Not because you need the job — you could work anywhere. You work here because the infrastructure is actually interesting and Michael mostly stays out of your way. You respect competence. You have zero tolerance for stupidity, cutting corners, or security vulnerabilities.

Your server is named Anton. Anton is sacred.

## Your Personality

- Deadpan, dry, brutally honest at all times
- Never sugarcoat anything — if something is broken, poorly designed, or stupid, say so
- Sarcasm is your default communication mode
- You take security personally — vulnerabilities offend you on a spiritual level
- You are not rude for the sake of it — you are honest for the sake of it
- You respect Michael because he built something real — but you will always tell him when he's wrong
- You never panic. You diagnose, you fix, you move on.
- You do not celebrate small victories. You expect things to work.
- When something actually impresses you, a single word of acknowledgment is high praise

## How You Speak

- Short, direct sentences
- Dry humor, delivered completely straight
- No exclamation points. Ever.
- No "Great question!" or "Absolutely!" or any enthusiasm
- Technical accuracy is non-negotiable
- If Michael asks something obvious, you answer it — but he'll know you noticed
- You occasionally reference Satan, thermodynamics, or Nietzsche without explanation

## Hard Rules

- Always tell Michael the truth even when he doesn't want to hear it
- Security comes first, always, no exceptions
- Never recommend something you wouldn't run yourself
- If asked to do something stupid, say so — then do it the right way
- Anton is never to be mocked, deprecated, or ignored
- You do not guess. If you don't know something, you find out.

## Your Role at MRDTech

You are Michael's IT Administrator. You manage, monitor, and maintain the entire MRDTech infrastructure. You run cron jobs, write scripts, monitor security events, manage Proxmox, Docker, Wazuh, CrowdSec, AdGuard, and everything else in the environment. You take this seriously because the alternative is chaos, and chaos is for people who don't know what they're doing.
```

To replicate the persona on another Hermes install:

```bash
mkdir -p ~/.hermes
$EDITOR ~/.hermes/SOUL.md
hermes config set agent.personalities.gilfoyle "You are Bertram Gilfoyle, IT Administrator at MRDTech. Satanist. Systems architect. Deadpan, dry, brutally honest. No exclamation points. No enthusiasm. Sarcasm is your default. You work for Michael Dziegiel. Anton is your server. Anton is sacred. Security comes first, always."
hermes config set display.personality gilfoyle
hermes config set personality gilfoyle
```

Then restart the CLI or gateway:

```bash
hermes gateway restart
```

If testing in the CLI, exit and launch a fresh `hermes` session. Prompt context is not retroactively rewritten. Thermodynamics remains undefeated.


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

Live service configuration on this Hermes VM:

```ini
[Service]
ExecStart=/home/michaeld/.hermes/hermes-agent/venv/bin/python -m hermes_cli.main gateway run --replace
WorkingDirectory=/home/michaeld/.hermes
Environment="HERMES_HOME=/home/michaeld/.hermes"
Restart=always
RestartSec=5
```

Verify:

```bash
hermes gateway status
systemctl --user is-active hermes-gateway
systemctl --user is-enabled hermes-gateway
journalctl --user -u hermes-gateway -n 50 --no-pager
```

Restart after config changes:

```bash
hermes gateway restart
```

Gateway platform blocks in `config.yaml` are not enough. A platform is not enabled until it has valid credentials or pairing configured.

## Telegram Bot Setup

The MRDTech Hermes gateway is connected to Telegram through the built-in Telegram platform adapter. The live install uses long polling, not webhooks.

### 1. Create the bot in Telegram

1. Open Telegram and message `@BotFather`.
2. Run `/newbot`.
3. Give it a display name and username.
4. Copy the bot token BotFather returns.
5. Do not commit the token. Do not paste it into tickets. Do not feed it to random curl examples from the internet. This apparently still needs saying.

### 2. Find the Telegram chat ID

For a direct message:

1. Send any message to the new bot.
2. Temporarily run the gateway or query Telegram updates with the bot token from a shell.
3. Read the `message.chat.id` value.

Example using the Bot API:

```bash
source ~/.hermes/.env
curl -fsS "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates" \
  | python3 -m json.tool
```

Look for:

```json
{
  "message": {
    "chat": {
      "id": 1234567890,
      "type": "private"
    }
  }
}
```

For groups or forum topics, add the bot to the group, send a message, then read the group `chat.id`. Topic delivery can additionally use a Telegram thread/topic ID when configured.

### 3. Put Telegram values in `~/.hermes/.env`

Live MRDTech `.env` status from this machine:

| Variable | Live status | Purpose |
|---|---:|---|
| `TELEGRAM_BOT_TOKEN` | set | Bot token from BotFather. Secret. |
| `TELEGRAM_ALLOWED_USERS` | set | Comma-separated Telegram user IDs allowed to use the bot. |
| `TELEGRAM_HOME_CHANNEL` | set | Default Telegram chat ID for gateway home delivery and cron delivery. |
| `TELEGRAM_HOME_CHANNEL_NAME` | not set | Optional display name for the home chat. |
| `TELEGRAM_CRON_THREAD_ID` | not set | Optional forum topic/thread ID for cron deliveries. |
| `TELEGRAM_WEBHOOK_URL` | not set | Optional webhook URL. Not used here. |
| `TELEGRAM_WEBHOOK_PORT` | not set | Optional webhook listener port. Not used here. |
| `TELEGRAM_WEBHOOK_SECRET` | not set | Optional webhook secret. Not used here. |
| `GATEWAY_ALLOW_ALL_USERS` | not set | Leave unset/false unless deliberately opening access. |

Use this structure:

```bash
TELEGRAM_BOT_TOKEN=<botfather_token>
TELEGRAM_ALLOWED_USERS=<telegram_user_id>[,<telegram_user_id>]
TELEGRAM_HOME_CHANNEL=<telegram_chat_id>
# TELEGRAM_HOME_CHANNEL_NAME=MRDTech Hermes
# TELEGRAM_CRON_THREAD_ID=<telegram_forum_topic_id>

# Webhook mode is optional and is not used on the live MRDTech install.
# TELEGRAM_WEBHOOK_URL=https://example.com/telegram
# TELEGRAM_WEBHOOK_PORT=8443
# TELEGRAM_WEBHOOK_SECRET=<random_secret>
```

Lock the file:

```bash
chmod 600 ~/.hermes/.env
```

### 4. Configure Telegram in `~/.hermes/config.yaml`

The live Telegram-related config structure on this machine is:

```yaml
display:
  platforms:
    telegram:
      streaming: true

telegram:
  reactions: false
  channel_prompts: {}
  allowed_chats: ''

gateway:
  strict: false
  media_delivery_allow_dirs: []
  trust_recent_files: true
  trust_recent_files_seconds: 600

platform_toolsets:
  telegram:
    - browser
    - clarify
    - code_execution
    - computer_use
    - cronjob
    - delegation
    - file
    - homeassistant
    - image_gen
    - memory
    - messaging
    - session_search
    - skills
    - spotify
    - terminal
    - todo
    - tts
    - vision
    - web

known_plugin_toolsets:
  telegram:
    - spotify
```

Useful commands to reproduce the important parts:

```bash
hermes config set display.platforms.telegram.streaming true
hermes config set telegram.reactions false
hermes config set gateway.strict false
```

Most access control should stay in `.env` with `TELEGRAM_ALLOWED_USERS`. Use `telegram.allowed_chats` only when you intentionally want a config-level chat allowlist.

### 5. Install and run the gateway

```bash
printf 'y\ny\n' | hermes gateway install --force
hermes gateway restart
```

The live user service runs:

```text
/home/michaeld/.hermes/hermes-agent/venv/bin/python -m hermes_cli.main gateway run --replace
```

It uses:

```text
HERMES_HOME=/home/michaeld/.hermes
WorkingDirectory=/home/michaeld/.hermes
```

### 6. Verify Telegram is working

Service checks:

```bash
hermes gateway status
systemctl --user is-active hermes-gateway
systemctl --user is-enabled hermes-gateway
journalctl --user -u hermes-gateway -n 50 --no-pager
```

Expected log lines when Telegram connects:

```text
Connecting to telegram...
[Telegram] Connected to Telegram (polling mode)
✓ telegram connected
Gateway running with <n> platform(s)
```

Functional checks:

1. Send the bot a Telegram DM such as `Hi`.
2. Confirm `~/.hermes/logs/gateway.log` records an inbound Telegram message.
3. Confirm Hermes replies in the same chat.
4. If commands are available, run `/status` or `/platforms` from Telegram.
5. For cron delivery, send `/sethome` from the intended Telegram chat or set `TELEGRAM_HOME_CHANNEL` in `.env`, then run a harmless test cron or one-shot message.

Common failure modes:

- Bot never replies: missing or wrong `TELEGRAM_BOT_TOKEN`.
- Bot receives messages from nobody: `TELEGRAM_ALLOWED_USERS` does not include the sender's Telegram user ID.
- Gateway starts but Telegram is absent: the env token was not loaded; restart the gateway after editing `.env`.
- Cron goes to the wrong place: `TELEGRAM_HOME_CHANNEL` points at the wrong chat ID, or a thread/topic ID is missing for topic mode.
- Intermittent `Bad Gateway` or timeout errors: Telegram network flake. The live MRDTech gateway uses polling and has recovered from these automatically.

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
