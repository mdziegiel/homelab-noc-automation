#!/usr/bin/env python3
"""
UniFi threat digest - daily 20:00 ET (00:00 UTC during EDT), no_agent.
Reports IDS/IPS detections (last 24h from the alarm log) and WAN status.
UDM-SE: login -> CSRF from JWT cookie -> /proxy/network/api/s/default/...
Stdlib only.
"""
import json, re, ssl, os, sys, time, base64, urllib.request, http.cookiejar
from collections import Counter
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ENV_PATH = os.path.expanduser("~/.hermes/.env")
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
TIMEOUT = 15
GW = "https://10.0.0.1"
NET = GW + "/proxy/network/api/s/default"

def load_env(p):
    d = {}
    for line in open(p, encoding="utf-8", errors="replace"):
        m = re.match(r'^([A-Za-z_]\w*)=(.*)$', line.rstrip("\n"))
        if m: d[m.group(1)] = m.group(2)
    return d
E = load_env(ENV_PATH)

def main():
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=CTX),
        urllib.request.HTTPCookieProcessor(cj))
    try:
        op.open(urllib.request.Request(
            f"{GW}/api/auth/login",
            data=json.dumps({"username": E.get("UNIFI_USERNAME", ""),
                             "password": E.get("UNIFI_PASSWORD", "")}).encode(),
            headers={"Content-Type": "application/json"}, method="POST"), timeout=TIMEOUT)
    except Exception as e:
        print(f"\u26a0\ufe0f UNIFI login failed: {type(e).__name__}: {str(e)[:120]}")
        return
    # CSRF token lives inside the TOKEN JWT cookie
    csrf = None
    tok = next((c.value for c in cj if c.name == "TOKEN"), None)
    if tok:
        try:
            p = tok.split(".")[1]; p += "=" * (-len(p) % 4)
            csrf = json.loads(base64.urlsafe_b64decode(p)).get("csrfToken")
        except Exception:
            pass
    hdr = {"Content-Type": "application/json"}
    if csrf:
        hdr["X-CSRF-Token"] = csrf

    def call(method, path, body=None):
        r = urllib.request.Request(NET + path, headers=hdr,
                                   data=(json.dumps(body).encode() if body else None), method=method)
        return json.loads(op.open(r, timeout=TIMEOUT).read())

    out = ["\U0001f6e1\ufe0f UNIFI threat digest (24h)"]

    # --- IDS/IPS alarms ---
    try:
        alarms = call("GET", "/list/alarm").get("data", [])
        cutoff = (time.time() - 86400) * 1000  # alarm 'time' is epoch ms
        def atime(a):
            return a.get("time") or a.get("timestamp") or 0
        recent = [a for a in alarms if atime(a) >= cutoff]
        ips = [a for a in recent if a.get("key") == "EVT_IPS_IpsAlert"
               or "ips" in (a.get("key", "").lower())
               or a.get("inner_alert_signature")]
        if not ips:
            out.append("  IDS/IPS: no threat alarms in last 24h")
        else:
            out.append(f"  \U0001f6a8 IDS/IPS: {len(ips)} detection(s) in last 24h")
            sig = Counter(a.get("inner_alert_signature", a.get("msg", "?")) for a in ips)
            cat = Counter(a.get("inner_alert_category", "") for a in ips if a.get("inner_alert_category"))
            for s, c in sig.most_common(6):
                out.append(f"    \u2022 {str(s)[:70]}: {c}")
            srcs = Counter(a.get("src_ip", a.get("srcip", "?")) for a in ips)
            top_src = ", ".join(f"{k}({v})" for k, v in srcs.most_common(3) if k and k != "?")
            if top_src:
                out.append(f"    top sources: {top_src}")
    except Exception as e:
        out.append(f"  IDS/IPS query failed: {type(e).__name__}: {str(e)[:90]}")

    # --- WAN status ---
    try:
        health = call("GET", "/stat/health").get("data", [])
        wan = next((h for h in health if h.get("subsystem") == "wan"), {})
        www = next((h for h in health if h.get("subsystem") == "www"), {})
        status = wan.get("status", "?")
        flag = "" if status == "ok" else "  \u26a0\ufe0f"
        out.append(f"  WAN: {status}  IP {wan.get('wan_ip','?')}  gw {wan.get('gw_name','?')}{flag}")
        if www.get("latency") is not None:
            out.append(f"  uplink: {www.get('latency')}ms latency, "
                       f"down {www.get('xput_down','?')} / up {www.get('xput_up','?')} Mbps")
    except Exception as e:
        out.append(f"  WAN query failed: {type(e).__name__}: {str(e)[:90]}")

    print("\n".join(out))

if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, 'UniFi Threat Digest', priority=6)
