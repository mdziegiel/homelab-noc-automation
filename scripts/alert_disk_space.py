#!/usr/bin/env python3
"""
Disk space alert - Proxmox storage volumes.
Cron: every 6h, no_agent. Silent unless a volume exceeds THRESHOLD% usage.
Stdlib only (VM108 has no pip). Auth/pitfalls per homelab-infra-monitoring skill.
"""
import json, re, ssl, os, sys, urllib.request
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

THRESHOLD = 85.0
ENV_PATH = os.path.expanduser("~/.hermes/.env")
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
TIMEOUT = 12

def load_env(p):
    d = {}
    for line in open(p, encoding="utf-8", errors="replace"):
        m = re.match(r'^([A-Za-z_]\w*)=(.*)$', line.rstrip("\n"))
        if m: d[m.group(1)] = m.group(2)   # last wins
    return d
E = load_env(ENV_PATH)

def jget(url, headers):
    r = urllib.request.Request(url, headers=headers)
    return json.loads(urllib.request.urlopen(r, timeout=TIMEOUT, context=CTX).read().decode("utf-8", "replace"))

def main():
    tid = E.get("PROXMOX_TOKEN_ID", "")
    if "!" not in tid and "@pam" in tid:        # repair dropped bang separator
        tid = tid.replace("@pam", "@pam!")
    sec = E.get("PROXMOX_TOKEN_SECRET", "")
    auth = {"Authorization": f"PVEAPIToken={tid}={sec}"}
    base = "https://10.0.0.251:8006/api2/json"
    try:
        nodes = jget(f"{base}/nodes", auth)["data"]
    except Exception as e:
        print(f"DISK ALERT: cannot reach Proxmox: {type(e).__name__}: {str(e)[:120]}")
        return
    breaches = []
    for n in nodes:
        node = n["node"]
        try:
            st = jget(f"{base}/nodes/{node}/storage", auth)["data"]
        except Exception as e:
            print(f"DISK ALERT: storage query failed on {node}: {type(e).__name__}: {str(e)[:90]}")
            continue
        for s in st:
            tot = s.get("total", 0)
            if not tot:
                continue
            pct = 100.0 * s.get("used", 0) / tot
            if pct > THRESHOLD:
                breaches.append((pct, node, s["storage"], s.get("used", 0), tot))
    if not breaches:
        return  # silent: all volumes healthy
    breaches.sort(reverse=True)
    out = [f"\u26a0\ufe0f DISK SPACE ALERT \u2014 {len(breaches)} volume(s) over {THRESHOLD:.0f}%"]
    for pct, node, name, used, tot in breaches:
        out.append(f"  {name} ({node}): {pct:.1f}%  {used/1e9:.0f}/{tot/1e9:.0f} GB")
    print("\n".join(out))

if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, 'Disk Space Alert', priority=8)
