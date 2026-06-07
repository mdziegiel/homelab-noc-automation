#!/usr/bin/env python3
"""
Wazuh->Telegram alerting heartbeat.
Runs weekly. Verifies the SAME delivery path Wazuh alerts use:
  1. api.telegram.org must resolve to a real (non-sinkhole) IP
  2. the bot sendMessage call must return ok:true
On SUCCESS: sends a heartbeat to the Telegram chat (positive weekly proof) and
            prints NOTHING -> the cron (no_agent) stays silent.
On FAILURE: prints a loud multi-line alert -> Hermes delivers it through the
            normal channel so a DNS block can't silently kill SIEM alerting.
Stdlib only.
"""
import os, re, ssl, json, socket, sys, urllib.request

ENV = os.path.expanduser("~/.hermes/.env")

def load_env(p):
    d = {}
    try:
        for line in open(p, encoding="utf-8", errors="replace"):
            m = re.match(r'^([A-Za-z_]\w*)=(.*)$', line.rstrip("\n"))
            if m:
                d[m.group(1)] = m.group(2)
    except Exception:
        pass
    return d

def gotify_fallback(msg):
    """Out-of-band alert via Gotify. Different domain than api.telegram.org, so
    a Telegram DNS block can't blind this path. Best-effort; never raises."""
    url = E.get("GOTIFY_URL", "").strip().rstrip("/")
    tok = E.get("GOTIFY_TOKEN", "").strip()
    if not url or not tok:
        return "skipped (GOTIFY_URL/GOTIFY_TOKEN not set)"
    body = json.dumps({
        "title": "Wazuh alerting heartbeat FAILED",
        "message": msg + "\n\nTelegram delivery path is down; this is the Gotify "
                         "fallback. Wazuh high/critical alerts may not reach you.",
        "priority": 8,
    }).encode()
    req = urllib.request.Request(f"{url}/message?token={tok}", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        # Gotify is HTTP on the LAN; no TLS context needed.
        with urllib.request.urlopen(req, timeout=10) as r:
            return f"sent (http {r.status})"
    except Exception as e:
        return f"FAILED ({e!r})"

def fail(msg):
    gf = gotify_fallback(msg)
    print("\U0001F6A8 WAZUH ALERTING HEARTBEAT FAILED")
    print(msg)
    print("Impact: Wazuh high/critical alerts will NOT reach Telegram until fixed.")
    print("Most likely cause: api.telegram.org got re-blocked by AdGuard DNS filtering.")
    print("Fix: AdGuard (http://10.0.0.21) -> Custom rules -> @@||api.telegram.org^")
    print(f"Gotify fallback: {gf}")
    sys.exit(0)   # exit 0: the printed text IS the alert payload

E = load_env(ENV)
tok = E.get("TELEGRAM_BOT_TOKEN", "").strip()
chat = E.get("TELEGRAM_HOME_CHANNEL", "").strip()
if not tok or not chat:
    fail("TELEGRAM_BOT_TOKEN or TELEGRAM_HOME_CHANNEL missing from ~/.hermes/.env")

# 1) DNS sanity: catch the 0.0.0.0 / :: sinkhole that broke this once before
try:
    infos = socket.getaddrinfo("api.telegram.org", 443, proto=socket.IPPROTO_TCP)
    ips = {i[4][0] for i in infos}
except Exception as e:
    fail(f"DNS resolution of api.telegram.org failed: {e!r}")
bad = {"0.0.0.0", "::", "127.0.0.1", "::1"}
real = [ip for ip in ips if ip not in bad]
if not real:
    fail(f"api.telegram.org resolves to a SINKHOLE ({sorted(ips)}) -> DNS-blocked.")

# 2) actual delivery
ca = "/etc/ssl/certs/ca-certificates.crt"
ctx = ssl.create_default_context(cafile=ca) if os.path.exists(ca) else ssl.create_default_context()
import datetime
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
text = (f"\u2705 Wazuh alerting heartbeat OK ({now})\n"
        f"api.telegram.org -> {real[0]} | bot delivery verified.\n"
        f"This is your weekly proof that SIEM->Telegram alerting still works.")
payload = {"chat_id": chat, "text": text, "disable_web_page_preview": True}
url = f"https://api.telegram.org/bot{tok}/sendMessage"
req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                            headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
        resp = json.loads(r.read())
except urllib.error.HTTPError as e:
    fail(f"Telegram API HTTP {e.code}: {e.read().decode()[:200]}")
except Exception as e:
    fail(f"Telegram sendMessage failed: {e!r}")

if not resp.get("ok"):
    fail(f"Telegram API returned ok=false: {json.dumps(resp)[:200]}")

# success -> stay silent (heartbeat already landed in Telegram)
sys.exit(0)
