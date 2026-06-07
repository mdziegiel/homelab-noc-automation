#!/usr/bin/env python3
"""
Certificate expiry alert - runs daily via Hermes cron (no_agent).
Alerts Telegram when any Uptime Kuma HTTPS monitor's TLS cert drops below
CERT_ALERT_DAYS (30) or becomes invalid. STATEFUL: only fires when a cert
newly crosses the threshold (or worsens by a bucket), so it does not nag every
day for the same slowly-approaching expiry. Silent when nothing newly crosses.

Reads /metrics with the API key as basic-auth password (empty username).
State: ~/.hermes/state/cert_expiry.json  -> {monitor: last_alerted_bucket}
"""
import base64, json, os, re, ssl, time, urllib.request

ENV_PATH = os.path.expanduser("~/.hermes/.env")
STATE = os.path.expanduser("~/.hermes/state/cert_expiry.json")
CERT_ALERT_DAYS = 30
TIMEOUT = 12
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def load_env(path):
    d = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line.rstrip("\n"))
            if m:
                d[m.group(1)] = m.group(2)
    return d


def bucket(days):
    """Coarse buckets so we alert on meaningful transitions, not every day."""
    if days <= 0:
        return "expired"
    if days <= 7:
        return "7d"
    if days <= 14:
        return "14d"
    if days <= 30:
        return "30d"
    return "ok"


def main():
    E = load_env(ENV_PATH)
    base = E.get("UPTIME_KUMA_URL", "").strip().rstrip("/")
    key = E.get("UPTIME_KUMA_API_KEY", "").strip()
    if not base or not key or key.startswith("<"):
        return  # silent: misconfig, nothing to do
    auth = {"Authorization": "Basic " + base64.b64encode(f":{key}".encode()).decode()}
    try:
        text = urllib.request.urlopen(
            urllib.request.Request(f"{base}/metrics", headers=auth),
            timeout=TIMEOUT, context=CTX).read().decode("utf-8", "replace")
    except Exception as e:
        print(f"\u26a0\ufe0f Cert expiry check FAILED to reach Uptime Kuma: {type(e).__name__}: {str(e)[:120]}")
        return

    cert_days, cert_valid = {}, {}
    for line in text.splitlines():
        if not line or line[0] == "#":
            continue
        m = re.search(r'monitor_name="([^"]*)"', line)
        if not m:
            continue
        name = m.group(1)
        try:
            val = float(line.rsplit("}", 1)[1])
        except (ValueError, IndexError):
            continue
        if line.startswith("monitor_cert_days_remaining{"):
            cert_days[name] = val
        elif line.startswith("monitor_cert_is_valid{"):
            cert_valid[name] = val

    # load state
    try:
        with open(STATE, encoding="utf-8") as f:
            last = json.load(f)
    except Exception:
        last = {}

    order = {"ok": 0, "30d": 1, "14d": 2, "7d": 3, "expired": 4, "invalid": 5}
    new_alerts = []
    cur_state = {}
    for name, days in cert_days.items():
        valid = cert_valid.get(name, 1) == 1
        b = "invalid" if not valid else bucket(days)
        cur_state[name] = b
        if b in ("ok",):
            continue
        prev = last.get(name, "ok")
        # alert only when crossing into a worse bucket than last alerted
        if order[b] > order.get(prev, 0):
            if b == "invalid":
                new_alerts.append(f"  {name}: cert INVALID")
            elif b == "expired":
                new_alerts.append(f"  {name}: cert EXPIRED")
            else:
                new_alerts.append(f"  {name}: cert expires in {int(days)}d")

    # persist current buckets (so recovery resets the baseline too)
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cur_state, f)
    os.replace(tmp, STATE)

    if new_alerts:
        now = time.strftime("%a %Y-%m-%d %H:%M %Z")
        print(f"\U0001f510 TLS CERT EXPIRY ALERT  -  {now}\n"
              f"{len(new_alerts)} certificate(s) crossed the {CERT_ALERT_DAYS}-day threshold:\n"
              + "\n".join(new_alerts))
    # else: silent (no_agent empty stdout = no message)


if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, 'TLS Cert Expiry Alert', priority=8)
