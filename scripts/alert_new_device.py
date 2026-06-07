#!/usr/bin/env python3
"""
New device alert - hourly via Hermes cron (no_agent). STATEFUL.
Polls UniFi for active + known clients and alerts Telegram the FIRST time a MAC
is seen. First run establishes a baseline silently (no flood). Subsequent new
MACs are reported once, then remembered. Silent when nothing new.

State: ~/.hermes/state/new_device.json
  {"known": {mac: {"name","ip","oui","first_seen","first_alert_epoch"}},
   "baselined": true}
"""
import base64, json, os, re, ssl, time, urllib.request, http.cookiejar

ENV_PATH = os.path.expanduser("~/.hermes/.env")
STATE = os.path.expanduser("~/.hermes/state/new_device.json")
TIMEOUT = 15
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
GW = "https://10.0.0.1"
NET = GW + "/proxy/network/api/s/default"


def load_env(path):
    d = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line.rstrip("\n"))
            if m:
                d[m.group(1)] = m.group(2)
    return d


def main():
    E = load_env(ENV_PATH)
    user = E.get("UNIFI_USERNAME", "")
    pw = E.get("UNIFI_PASSWORD", "")
    if not user or not pw or pw.startswith("<"):
        return  # silent: misconfig

    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=CTX),
        urllib.request.HTTPCookieProcessor(cj))
    try:
        op.open(urllib.request.Request(
            GW + "/api/auth/login",
            data=json.dumps({"username": user, "password": pw}).encode(),
            headers={"Content-Type": "application/json"}, method="POST"), timeout=TIMEOUT)
    except Exception as e:
        print(f"\u26a0\ufe0f New-device check FAILED to reach UniFi: {type(e).__name__}: {str(e)[:120]}")
        return

    def call(path):
        return json.loads(op.open(urllib.request.Request(NET + path, method="GET"),
                                  timeout=TIMEOUT).read())

    # Active clients now. (Active = currently connected; this is the set we
    # want to detect arrivals on. Stateful memory prevents re-alerting.)
    try:
        sta = call("/stat/sta").get("data", [])
    except Exception as e:
        print(f"\u26a0\ufe0f New-device check FAILED listing clients: {type(e).__name__}: {str(e)[:120]}")
        return

    now = time.time()
    current = {}
    for c in sta:
        mac = (c.get("mac") or "").lower()
        if not mac:
            continue
        current[mac] = {
            "name": c.get("name") or c.get("hostname") or "",
            "ip": c.get("ip", ""),
            "oui": c.get("oui", ""),
            "wired": bool(c.get("is_wired")),
            "first_seen": c.get("first_seen", 0),
        }

    # load state
    try:
        with open(STATE, encoding="utf-8") as f:
            st = json.load(f)
    except Exception:
        st = {}
    known = st.get("known", {})
    baselined = st.get("baselined", False)

    new_macs = [m for m in current if m not in known]

    out_lines = []
    if not baselined:
        # First run: adopt everything as baseline, no alert.
        for m in current:
            known[m] = dict(current[m], first_alert_epoch=now)
        msg = None
    else:
        for m in new_macs:
            info = current[m]
            known[m] = dict(info, first_alert_epoch=now)
            label = info["name"] or "(unnamed)"
            conn = "wired" if info["wired"] else "wireless"
            out_lines.append(
                f"  {label}  [{m}]\n"
                f"    IP {info['ip'] or '?'} · {conn} · {info['oui'] or 'unknown vendor'}")
        msg = out_lines

    # persist
    st = {"known": known, "baselined": True}
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, indent=0)
    os.replace(tmp, STATE)

    if msg:
        ts = time.strftime("%a %Y-%m-%d %H:%M %Z")
        print(f"\U0001f6f0\ufe0f NEW DEVICE ON NETWORK  -  {ts}\n"
              f"{len(msg)} new client(s) detected on UniFi:\n" + "\n".join(msg))
    # else silent (first-run baseline or nothing new)


if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, 'New Device Alert', priority=6)
