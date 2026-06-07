#!/usr/bin/env python3
"""
PBS backup verification - last 24h task results.
Cron: daily 08:00 ET (12:00 UTC during EDT), no_agent.
Reports backup/verify failures from the last 24h. Always prints a short summary
line (this is a daily report, not a silent watchdog).
Stdlib only.
"""
import json, re, ssl, os, sys, time, urllib.request, urllib.parse
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ENV_PATH = os.path.expanduser("~/.hermes/.env")
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
TIMEOUT = 15
PBS = "https://10.0.0.77:8007/api2/json"

def load_env(p):
    d = {}
    for line in open(p, encoding="utf-8", errors="replace"):
        m = re.match(r'^([A-Za-z_]\w*)=(.*)$', line.rstrip("\n"))
        if m: d[m.group(1)] = m.group(2)
    return d
E = load_env(ENV_PATH)

def main():
    try:
        tk = json.loads(urllib.request.urlopen(urllib.request.Request(
            f"{PBS}/access/ticket",
            data=urllib.parse.urlencode({
                "username": E.get("PBS_USERNAME", "root@pam"),
                "password": E.get("PBS_PASSWORD", "")}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST"), timeout=TIMEOUT, context=CTX).read())["data"]["ticket"]
    except Exception as e:
        print(f"\u26a0\ufe0f PBS BACKUP: login failed: {type(e).__name__}: {str(e)[:120]}")
        return
    cookie = {"Cookie": f"PBSAuthCookie={urllib.parse.quote(tk, safe='')}"}
    since = int(time.time()) - 86400
    try:
        tasks = json.loads(urllib.request.urlopen(urllib.request.Request(
            f"{PBS}/nodes/localhost/tasks?since={since}&limit=500", headers=cookie),
            timeout=TIMEOUT, context=CTX).read())["data"]
    except Exception as e:
        print(f"\u26a0\ufe0f PBS BACKUP: task query failed: {type(e).__name__}: {str(e)[:120]}")
        return

    backups = [t for t in tasks if t.get("worker_type") == "backup"]
    verifies = [t for t in tasks if t.get("worker_type") == "verify"]
    failures = []
    for t in tasks:
        s = t.get("status", "running")
        if "endtime" not in t or s == "running":
            continue
        if s != "OK":
            failures.append((t.get("worker_type", "?"), t.get("worker_id", ""), str(s)[:110]))

    bk_ok = sum(1 for t in backups if t.get("status") == "OK")
    vf_ok = sum(1 for t in verifies if t.get("status") == "OK")
    head = "\u2705 PBS BACKUPS OK" if not failures else f"\u26a0\ufe0f PBS \u2014 {len(failures)} task(s) FAILED (24h)"
    out = [head,
           f"  backups: {bk_ok}/{len(backups)} OK   verifies: {vf_ok}/{len(verifies)} OK"]
    for wt, wid, msg in failures[:10]:
        tail = wid.split(":")[0] if wid else ""
        out.append(f"  FAIL {wt} {tail}: {msg}")
    print("\n".join(out))

if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, 'PBS Backup Report', priority=5)
