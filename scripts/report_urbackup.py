#!/usr/bin/env python3
"""
URBackup backup report - daily 8am ET.
Runs via Hermes cron (no_agent). stdout delivered verbatim to Telegram.
Reports client count, last file/image backup times, and any clients whose
last backup is stale (>26h) or flagged with backup issues. Stdlib only.

URBackup web API auth flow (verified live on 2.5.x, api_version 2):
  1. POST /x?a=salt  body 'username=<u>'  -> {salt, rnd, pbkdf2_rounds, ses}
  2. pwmd5 = md5(salt+password); if pbkdf2_rounds>0:
        pwmd5 = pbkdf2_hmac('sha256', bytes.fromhex(pwmd5), salt, rounds, 32).hex()
     final = md5(rnd + pwmd5)
  3. POST /x?a=login&ses=<ses>  body 'username=<u>&password=<final>'
  4. POST /x?a=status&ses=<ses> -> {status:[clients...]}
Note: the web user is 'admin' (URBACKUP_USERNAME in .env).
"""
import hashlib, json, os, re, ssl, time, urllib.request, urllib.parse

ENV_PATH = os.path.expanduser("~/.hermes/.env")
TIMEOUT = 12
STALE_H = 26
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def load_env(path):
    d = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line.rstrip("\n"))
            if m:
                d[m.group(1)] = m.group(2)  # last-wins
    return d


def urb_api(base, action, ses=None, body=""):
    url = base + "/x?a=" + action
    if ses:
        url += "&ses=" + ses
    r = urllib.request.Request(url, data=body.encode(), method="POST",
                               headers={"Content-Type": "application/json; charset=utf-8"})
    raw = urllib.request.urlopen(r, timeout=TIMEOUT, context=CTX).read().decode("utf-8", "replace")
    return json.loads(raw)


def urb_status(base, user, pw):
    s = urb_api(base, "salt", body="username=" + urllib.parse.quote(user))
    if s.get("error") == 1 or not s.get("salt"):
        raise RuntimeError("URBackup user not found: " + user)
    salt = s.get("salt", "")
    rnd = s.get("rnd", "")
    rounds = int(s.get("pbkdf2_rounds", 0) or 0)
    ses = s.get("ses")
    pwmd5 = hashlib.md5((salt + pw).encode()).hexdigest()
    if rounds > 0:
        pwmd5 = hashlib.pbkdf2_hmac("sha256", bytes.fromhex(pwmd5), salt.encode(), rounds, dklen=32).hex()
    final = hashlib.md5((rnd + pwmd5).encode()).hexdigest()
    body = "username=" + urllib.parse.quote(user) + "&password=" + final
    if ses:
        body += "&ses=" + ses
    r3 = urb_api(base, "login", body=body)
    if not r3.get("success"):
        raise RuntimeError("URBackup login failed (error %s)" % r3.get("error"))
    ses = r3.get("session") or ses
    st = urb_api(base, "status", body="ses=" + ses if ses else "")
    return st.get("status", [])


def ago(epoch):
    if not epoch:
        return "never"
    h = (time.time() - epoch) / 3600.0
    if h < 1:
        return f"{h*60:.0f}m ago"
    if h < 48:
        return f"{h:.1f}h ago"
    return f"{h/24:.1f}d ago"


def main():
    E = load_env(ENV_PATH)
    base = E.get("URBACKUP_URL", "http://10.0.0.76:55414").rstrip("/")
    user = E.get("URBACKUP_USERNAME", "admin")
    pw = E.get("URBACKUP_PASSWORD", "")
    now = time.strftime("%a %Y-%m-%d %H:%M %Z")
    if not pw or pw.startswith("<"):
        print("URBackup report: URBACKUP_PASSWORD not set in .env")
        return
    try:
        clients = urb_status(base, user, pw)
    except Exception as e:
        print(f"URBackup Report  -  {now}\n{'='*38}\nERROR: {type(e).__name__}: {str(e)[:160]}")
        return

    total = len(clients)
    online = sum(1 for c in clients if c.get("online"))
    problems = []
    rows = []
    for c in sorted(clients, key=lambda x: x.get("name", "")):
        name = c.get("name", "?")
        lf = c.get("lastbackup", 0) or 0
        li = c.get("lastbackup_image", 0) or 0
        file_ok = c.get("file_ok", False)
        image_ok = c.get("image_ok", False)
        issues = c.get("last_filebackup_issues", 0) or 0
        on = c.get("online")
        rows.append(f"  {name} [{'online' if on else 'OFFLINE'}]")
        rows.append(f"    file:  {ago(lf)}{' OK' if file_ok else ' (not ok)'}"
                    + (f"  issues={issues}" if issues else ""))
        rows.append(f"    image: {ago(li)}{' OK' if image_ok else ' (n/a)'}")
        # failure detection: stale file backup or explicit not-ok or issues
        lf_h = (time.time() - lf) / 3600.0 if lf else 1e9
        if lf == 0:
            problems.append(f"{name}: no file backup on record")
        elif lf_h > STALE_H:
            problems.append(f"{name}: last file backup {ago(lf)} (>{STALE_H}h)")
        if issues:
            problems.append(f"{name}: {issues} file backup issue(s) in last run")
        if not on:
            problems.append(f"{name}: client OFFLINE")

    head = "ALL GREEN" if not problems else f"{len(problems)} item(s) need attention"
    out = [f"URBackup Report  -  {now}", "=" * 38, head,
           f"clients: {total} ({online} online)", ""]
    out += rows
    if problems:
        out.append("\nNEEDS ATTENTION:")
        for p in problems:
            out.append(f"  - {p}")
    print("\n".join(out))


if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, 'URBackup Report', priority=5)
