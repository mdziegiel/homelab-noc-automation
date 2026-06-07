# Wazuh Hardening & Integration

Drop-in configuration for a Wazuh 4.x manager: brute-force active response,
Telegram alerting, and a low-noise Sysmon detection ruleset for Windows agents.

## Files

| File | Target location on Wazuh manager | Purpose |
|------|----------------------------------|---------|
| `ossec.conf.additions.xml` | merge into `/var/ossec/etc/ossec.conf` | `<active-response>` (firewall-drop) + Telegram `<integration>` |
| `local_rules.xml` | `/var/ossec/etc/rules/local_rules.xml` | Rule 100100 (brute-force) + custom Sysmon rules 100300–100322 |
| `custom-telegram.py` | `/var/ossec/integrations/custom-telegram.py` | Telegram push integration (stdlib only) |
| `custom-telegram` | `/var/ossec/integrations/custom-telegram` | Wrapper Wazuh invokes |
| `windows-agent-sysmon.xml` | each Windows agent `ossec.conf` | Collects the Sysmon eventchannel |

## What the rules do

### Rule 100100 — SSH brute force
Fires after **exactly 5 failed logins from the same source IP within 120s**
(`if_matched_sid 5710`, `frequency=5`, `timeframe=120`, `same_source_ip`).
Wired to the `firewall-drop` active response with a **600-second** block.

### Sysmon detections (low-noise, suspicious-pattern only)
Chained off the stock Sysmon base SIDs so they only fire on genuinely
suspicious shapes — not on every event. Each carries a MITRE ATT&CK mapping.

| Rule | Lvl | Event | Detects |
|------|-----|-------|---------|
| 100300 | 10 | E3 Network | LOLBins (rundll32/regsvr32/mshta/certutil…) making network connections (T1105) |
| 100301 | 9 | E3 Network | Binaries in %TEMP%/%APPDATA%/Downloads beaconing out (T1071) |
| 100310 | 9 | E7 ImageLoad | DLL side-loading from user-writable paths (T1574.002) |
| 100311 | 11 | E7 ImageLoad | Credential-access DLLs (samlib/vaultcli/cryptdll…) loaded by suspicious binaries (T1003) |
| 100320 | 8 | E12/13 Registry | Run/RunOnce ASEP persistence writes (T1547.001) |
| 100321 | 11 | E12/13 Registry | Winlogon / IFEO Debugger / AppInit_DLLs / service ImagePath hijacks (T1546.008) |
| 100322 | 10 | E14 Registry | Registry renames touching Defender/security services (T1562.001) |

The design keeps routine Sysmon volume silent and surfaces only the bad shapes.

## Apply

```bash
# 1. Install the Telegram integration scripts
sudo install -m 750 -o root -g wazuh custom-telegram    /var/ossec/integrations/custom-telegram
sudo install -m 750 -o root -g wazuh custom-telegram.py /var/ossec/integrations/custom-telegram.py

# 2. Merge the active-response + integration blocks into ossec.conf
#    (inside the top-level <ossec_config>). Fill in your real bot token + chat id.
sudo $EDITOR /var/ossec/etc/ossec.conf

# 3. Append the rules to local_rules.xml
sudo bash -c 'cat local_rules.xml >> /var/ossec/etc/rules/local_rules.xml'
sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml

# 4. Validate the ruleset compiles (no errors on 1003xx / 100100)
printf 'test\n' | sudo /var/ossec/bin/wazuh-logtest

# 5. Restart — ideally behind a rollback guard that restores the backup
#    and restarts again if the manager fails to come up.
sudo systemctl restart wazuh-manager
```

## Telegram integration notes

`custom-telegram.py` is **stdlib only** (no `requests` dependency) and builds an
SSL context against the system CA bundle (`/etc/ssl/certs/ca-certificates.crt`),
because Wazuh's bundled framework Python defaults its CA path to a location that
does not exist on Debian/Ubuntu — without this it fails with
`CERTIFICATE_VERIFY_FAILED`.

> **Gotcha learned the hard way:** if `api.telegram.org` resolves to `0.0.0.0`,
> your DNS filtering (AdGuard/Pi-hole) is sinkholing it. Allowlist it:
> `@@||api.telegram.org^`. A blocked Telegram domain silently kills SIEM
> alerting — pair this with a heartbeat check (see `scripts/telegram_heartbeat.py`).

## Windows agents (Sysmon)

Install Sysmon with a good config (e.g. SwiftOnSecurity's) on each Windows host,
then add `windows-agent-sysmon.xml`'s `<localfile>` block to the agent's
`ossec.conf` and restart the agent. Verify events arrive:

```
data.win.system.providerName : "Microsoft-Windows-Sysmon"
```
