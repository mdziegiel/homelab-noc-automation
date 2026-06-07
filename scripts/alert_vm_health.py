#!/usr/bin/env python3
"""
VM health check - Proxmox QEMU VMs.
Cron: every 30m, no_agent. Stateful: alerts only when a VM that was RUNNING on the
previous check is no longer running (an unexpected drop), and once when it recovers.
A VM that is already stopped (planned/known) does NOT re-alert every cycle.
State file: ~/.hermes/state/vm_health.json
Stdlib only.
"""
import json, re, ssl, os, time, sys, urllib.request
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ENV_PATH = os.path.expanduser("~/.hermes/.env")
STATE = os.path.expanduser("~/.hermes/state/vm_health.json")
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
TIMEOUT = 12

def load_env(p):
    d = {}
    for line in open(p, encoding="utf-8", errors="replace"):
        m = re.match(r'^([A-Za-z_]\w*)=(.*)$', line.rstrip("\n"))
        if m: d[m.group(1)] = m.group(2)
    return d
E = load_env(ENV_PATH)

def jget(url, headers):
    r = urllib.request.Request(url, headers=headers)
    return json.loads(urllib.request.urlopen(r, timeout=TIMEOUT, context=CTX).read().decode("utf-8", "replace"))

def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {}

def save_state(s):
    tmp = STATE + ".tmp"
    json.dump(s, open(tmp, "w"))
    os.replace(tmp, STATE)

def main():
    tid = E.get("PROXMOX_TOKEN_ID", "")
    if "!" not in tid and "@pam" in tid:
        tid = tid.replace("@pam", "@pam!")
    sec = E.get("PROXMOX_TOKEN_SECRET", "")
    auth = {"Authorization": f"PVEAPIToken={tid}={sec}"}
    base = "https://10.0.0.251:8006/api2/json"
    try:
        nodes = jget(f"{base}/nodes", auth)["data"]
    except Exception as e:
        print(f"VM HEALTH: cannot reach Proxmox: {type(e).__name__}: {str(e)[:120]}")
        return

    cur = {}   # vmid -> {"name","status","node"}
    for n in nodes:
        node = n["node"]
        try:
            vms = jget(f"{base}/nodes/{node}/qemu", auth)["data"]
        except Exception as e:
            print(f"VM HEALTH: qemu query failed on {node}: {type(e).__name__}: {str(e)[:90]}")
            return
        for v in vms:
            cur[str(v["vmid"])] = {"name": v.get("name", ""), "status": v.get("status", "?"), "node": node}

    prev = load_state()
    newly_down, recovered = [], []
    for vmid, info in cur.items():
        was = prev.get(vmid, {}).get("status")
        now = info["status"]
        if was == "running" and now != "running":
            newly_down.append((vmid, info["name"], now, info["node"]))
        elif was and was != "running" and now == "running":
            recovered.append((vmid, info["name"], info["node"]))

    save_state(cur)   # always persist latest snapshot

    if not newly_down and not recovered:
        return  # silent

    out = []
    if newly_down:
        out.append(f"\U0001f534 VM DOWN \u2014 {len(newly_down)} VM(s) stopped unexpectedly")
        for vmid, name, status, node in sorted(newly_down):
            out.append(f"  {vmid} {name} ({node}): now {status}")
    if recovered:
        out.append(f"\u2705 RECOVERED \u2014 {len(recovered)} VM(s) back up")
        for vmid, name, node in sorted(recovered):
            out.append(f"  {vmid} {name} ({node})")
    print("\n".join(out))

if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, 'VM Health Alert', priority=8)
