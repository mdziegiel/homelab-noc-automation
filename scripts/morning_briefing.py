#!/usr/bin/env python3
"""
Homelab Morning Briefing
Runs daily at 07:00 via Hermes cron (no_agent). stdout is delivered verbatim to Telegram.
Each source is isolated: one failure never kills the briefing. Stdlib only (no pip on VM108).
"""
import json, re, ssl, time, urllib.request, urllib.parse, urllib.error, http.cookiejar, os

ENV_PATH = os.path.expanduser("~/.hermes/.env")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
TIMEOUT = 12

def load_env(path):
    d = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line.rstrip("\n"))
            if m:
                d[m.group(1)] = m.group(2)  # last definition wins (handles dup blocks)
    return d

E = load_env(ENV_PATH)

def req(url, headers=None, data=None, method=None, cookiejar=None):
    h = headers or {}
    if isinstance(data, dict):
        data = json.dumps(data).encode(); h.setdefault("Content-Type", "application/json")
    elif isinstance(data, str):
        data = data.encode()
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    if cookiejar is not None:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=CTX),
            urllib.request.HTTPCookieProcessor(cookiejar))
        resp = opener.open(r, timeout=TIMEOUT)
    else:
        resp = urllib.request.urlopen(r, timeout=TIMEOUT, context=CTX)
    return resp.read().decode("utf-8", "replace")

def jget(url, headers=None, data=None, method=None, cookiejar=None):
    return json.loads(req(url, headers, data, method, cookiejar))

# ---------------- Proxmox ----------------
def proxmox():
    tid = E.get("PROXMOX_TOKEN_ID", "")
    if "!" not in tid and "@pam" in tid:      # repair dropped bang separator
        tid = tid.replace("@pam", "@pam!")
    sec = E.get("PROXMOX_TOKEN_SECRET", "")
    auth = {"Authorization": f"PVEAPIToken={tid}={sec}"}
    base = "https://10.0.0.251:8006/api2/json"
    nodes = jget(f"{base}/nodes", auth)["data"]
    lines, node = [], None
    for n in nodes:
        node = n["node"]
        up = int(n.get("uptime", 0)); days = up // 86400
        lines.append(f"  node {n['node']}: {n.get('status')} (up {days}d), "
                     f"CPU {n.get('cpu',0)*100:.0f}%, "
                     f"mem {n.get('mem',0)/1e9:.1f}/{n.get('maxmem',1)/1e9:.0f}G")
    vms = jget(f"{base}/nodes/{node}/qemu", auth)["data"]
    if vms:
        run = [v for v in vms if v.get("status") == "running"]
        stop = [v for v in vms if v.get("status") != "running"]
        lines.append(f"  VMs: {len(run)}/{len(vms)} running")
        for v in sorted(stop, key=lambda x: int(x["vmid"])):
            lines.append(f"    DOWN: {v['vmid']} {v.get('name','')}")
    else:
        lines.append("  VMs: token has NO ACL grant -> 0 visible. "
                     "Fix: pveum acl modify / -token 'root@pam!YOUR_TOKEN_NAME' -role PVEAuditor")
    return "\n".join(lines)

# ---------------- Proxmox storage / disk ----------------
def disk():
    tid = E.get("PROXMOX_TOKEN_ID", "")
    if "!" not in tid and "@pam" in tid:
        tid = tid.replace("@pam", "@pam!")
    sec = E.get("PROXMOX_TOKEN_SECRET", "")
    auth = {"Authorization": f"PVEAPIToken={tid}={sec}"}
    st = jget("https://10.0.0.251:8006/api2/json/nodes/proxmox/storage", auth)["data"]
    if not st:
        return "  no storage visible (same token ACL issue as above)"
    out = []
    for s in sorted(st, key=lambda x: x.get("used", 0), reverse=True):
        if not s.get("total"):
            continue
        used, tot = s.get("used", 0), s.get("total", 1)
        pct = 100 * used / tot
        flag = "  <-- LOW" if pct > 85 else ""
        out.append(f"  {s['storage']:18} {used/1e9:7.1f}/{tot/1e9:7.1f}G {pct:5.1f}%{flag}")
    return "\n".join(out) if out else "  (no sized volumes reported)"

# ---------------- PBS backups (last 24h) ----------------
def pbs():
    tk = jget("https://10.0.0.77:8007/api2/json/access/ticket",
              data=urllib.parse.urlencode({
                  "username": E.get("PBS_USERNAME", "root@pam"),
                  "password": E.get("PBS_PASSWORD", "")}),
              headers={"Content-Type": "application/x-www-form-urlencoded"},
              method="POST")["data"]["ticket"]
    since = int(time.time()) - 86400
    cookie = {"Cookie": f"PBSAuthCookie={urllib.parse.quote(tk, safe='')}"}
    tasks = jget(f"https://10.0.0.77:8007/api2/json/nodes/localhost/tasks"
                 f"?since={since}&limit=500", cookie)["data"]
    if not tasks:
        return "  no PBS tasks logged in last 24h"
    ok = fail = run = 0
    bad = []
    for t in tasks:
        s = t.get("status", "running")
        if s == "running" or "endtime" not in t:
            run += 1
        elif s == "OK":
            ok += 1
        else:
            fail += 1
            bad.append(f"    FAIL {t.get('worker_type')}: {str(s)[:90]}")
    out = [f"  tasks 24h: {ok} OK, {fail} failed, {run} running"]
    out += bad[:6]
    return "\n".join(out)

# ---------------- Wazuh ----------------
def wazuh():
    jwt = req("https://10.0.0.233:55000/security/user/authenticate?raw=true",
              {"Authorization": "Basic " + _b64(f"{E.get('WAZUH_API_USER', 'YOUR_WAZUH_API_USER')}:{E.get('WAZUH_API_PASSWORD','')}")}).strip()
    ag = jget("https://10.0.0.233:55000/agents?limit=500",
              {"Authorization": f"Bearer {jwt}"})["data"]["affected_items"]
    active = [a for a in ag if a.get("status") == "active"]
    bad = [a for a in ag if a.get("status") != "active"]
    out = [f"  agents: {len(active)}/{len(ag)} active"]
    for a in bad:
        out.append(f"    {a.get('status','?').upper()}: {a.get('id')} {a.get('name','')}")
    return "\n".join(out)

def _b64(s):
    import base64; return base64.b64encode(s.encode()).decode()

# ---------------- CrowdSec ----------------
def crowdsec():
    dec = jget("http://10.0.0.237:18080/v1/decisions",
               {"X-Api-Key": E.get("CROWDSEC_API_KEY", "")})
    if not isinstance(dec, list):
        return "  unexpected response"
    from collections import Counter
    by_origin = Counter(d.get("origin", "?") for d in dec)
    by_scen = Counter(d.get("scenario", "?") for d in dec)
    top = ", ".join(f"{k}:{v}" for k, v in by_origin.most_common(4))
    out = [f"  active decisions: {len(dec)}", f"  by origin: {top}"]
    live = [d for d in dec if d.get("origin") not in ("lists",)]
    if live:
        out.append(f"  non-list (behavioral) bans: {len(live)}")
        for k, v in by_scen.most_common(3):
            if k != "?":
                out.append(f"    {k}: {v}")
    return "\n".join(out)

# ---------------- AdGuard ----------------
def adguard():
    s = jget("http://10.0.0.21/control/stats",
             {"Authorization": "Basic " + _b64(f"mdziegiel:{E.get('ADGUARD_PASSWORD','')}")})
    tot = s.get("num_dns_queries", 0)
    blk = s.get("num_blocked_filtering", 0)
    pct = (100 * blk / tot) if tot else 0
    out = [f"  queries: {tot:,}  blocked: {blk:,} ({pct:.1f}%)",
           f"  avg processing: {s.get('avg_processing_time',0)*1000:.1f} ms"]
    tq = s.get("top_queried_domains", [])[:3]
    if tq:
        names = ", ".join(list(x.keys())[0] for x in tq)
        out.append(f"  top queried: {names}")
    return "\n".join(out)

# ---------------- UniFi WAN ----------------
def unifi():
    cj = http.cookiejar.CookieJar()
    req("https://10.0.0.1/api/auth/login",
        data={"username": E.get("UNIFI_USERNAME", ""), "password": E.get("UNIFI_PASSWORD", "")},
        method="POST", cookiejar=cj)
    health = jget("https://10.0.0.1/proxy/network/api/s/default/stat/health",
                  cookiejar=cj)["data"]
    wan = next((h for h in health if h.get("subsystem") == "wan"), {})
    www = next((h for h in health if h.get("subsystem") == "www"), {})
    status = wan.get("status", "?")
    flag = "" if status == "ok" else "  <-- CHECK"
    out = [f"  WAN: {status}  IP {wan.get('wan_ip','?')}  gw {wan.get('gw_name','?')}{flag}"]
    if www.get("latency") is not None:
        out.append(f"  latency {www.get('latency')}ms, "
                   f"down {www.get('xput_down','?')} / up {www.get('xput_up','?')} Mbps")
    return "\n".join(out)

# ---------------- Docker via Portainer ----------------
def docker():
    base = E.get("PORTAINER_URL", "").strip().rstrip("/")
    user = E.get("PORTAINER_USERNAME", "").strip()
    pw = E.get("PORTAINER_PASSWORD", "").strip()
    if not base or not user or not pw or pw.startswith("<"):
        return ("  UNAVAILABLE - Portainer credentials not set.\n"
                "  Set PORTAINER_URL, PORTAINER_USERNAME, PORTAINER_PASSWORD in .env.")
    # 1. auth -> JWT
    jwt = jget(f"{base}/api/auth", data={"Username": user, "Password": pw},
               method="POST")["jwt"]
    auth = {"Authorization": f"Bearer {jwt}"}
    # 2. enumerate endpoints (each = a Docker environment)
    endpoints = jget(f"{base}/api/endpoints", auth)
    out = []
    total_run = total = 0
    for ep in endpoints:
        epid = ep.get("Id")
        epname = ep.get("Name", str(epid))
        try:
            cs = jget(f"{base}/api/endpoints/{epid}/docker/containers/json?all=1", auth)
        except Exception as e:
            out.append(f"  [{epname}] unreachable: {type(e).__name__}")
            continue
        run = [c for c in cs if c.get("State") == "running"]
        unhealthy = [c for c in cs if "unhealthy" in (c.get("Status", "").lower())]
        stopped = [c for c in cs if c.get("State") != "running"]
        total_run += len(run); total += len(cs)
        out.append(f"  [{epname}] {len(run)}/{len(cs)} running")
        for c in unhealthy:
            out.append(f"    UNHEALTHY: {c.get('Names',['?'])[0].lstrip('/')}")
        for c in stopped:
            out.append(f"    stopped: {c.get('Names',['?'])[0].lstrip('/')} ({c.get('Status','')})")
    if len(endpoints) > 1:
        out.insert(0, f"  total: {total_run}/{total} running across {len(endpoints)} environments")
    return "\n".join(out) if out else "  no Docker environments found in Portainer"

# ---------------- Uptime Kuma ----------------
def uptime_kuma():
    base = E.get("UPTIME_KUMA_URL", "").strip().rstrip("/")
    key = E.get("UPTIME_KUMA_API_KEY", "").strip()
    if not base or not key or key.startswith("<"):
        return ("  UNAVAILABLE - Uptime Kuma URL/API key not set.\n"
                "  Set UPTIME_KUMA_URL, UPTIME_KUMA_API_KEY in .env.")
    # API key is used as the basic-auth password (empty username) on /metrics
    auth = {"Authorization": "Basic " + _b64(f":{key}")}
    text = req(f"{base}/metrics", auth)
    status, rt = {}, {}
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
        if line.startswith("monitor_status{"):
            status[name] = val
        elif line.startswith("monitor_response_time{"):
            rt[name] = val
    if not status:
        return "  no monitors reported by /metrics"
    SMAP = {0: "DOWN", 1: "UP", 2: "PENDING", 3: "MAINT"}
    down = [k for k, v in status.items() if v == 0]
    other = [(k, SMAP.get(v, str(v))) for k, v in status.items() if v not in (0, 1)]
    up = sum(1 for v in status.values() if v == 1)
    out = [f"  monitors: {up}/{len(status)} up, {len(down)} down"]
    for k in sorted(down):
        out.append(f"    DOWN: {k}")
    for k, s in other:
        out.append(f"    {s}: {k}")
    return "\n".join(out)

# ---------------- URBackup ----------------
def urbackup():
    base = E.get("URBACKUP_URL", "http://10.0.0.76:55414").rstrip("/")
    user = E.get("URBACKUP_USERNAME", "admin")
    pw = E.get("URBACKUP_PASSWORD", "")
    if not pw or pw.startswith("<"):
        return "  UNAVAILABLE - URBACKUP_PASSWORD not set in .env."

    def api(action, body=""):
        url = base + "/x?a=" + action
        r = urllib.request.Request(url, data=body.encode(), method="POST",
                                   headers={"Content-Type": "application/json; charset=utf-8"})
        return json.loads(urllib.request.urlopen(r, timeout=TIMEOUT, context=CTX).read().decode("utf-8", "replace"))

    s = api("salt", "username=" + urllib.parse.quote(user))
    if s.get("error") == 1 or not s.get("salt"):
        return "  CHECK - URBackup user not found"
    salt, rnd = s.get("salt", ""), s.get("rnd", "")
    rounds = int(s.get("pbkdf2_rounds", 0) or 0)
    ses = s.get("ses")
    import hashlib as _h
    pwmd5 = _h.md5((salt + pw).encode()).hexdigest()
    if rounds > 0:
        pwmd5 = _h.pbkdf2_hmac("sha256", bytes.fromhex(pwmd5), salt.encode(), rounds, dklen=32).hex()
    final = _h.md5((rnd + pwmd5).encode()).hexdigest()
    body = "username=" + urllib.parse.quote(user) + "&password=" + final
    if ses:
        body += "&ses=" + ses
    r3 = api("login", body)
    if not r3.get("success"):
        return "  CHECK - URBackup login failed"
    ses = r3.get("session") or ses
    clients = api("status", "ses=" + ses if ses else "").get("status", [])
    total = len(clients)
    online = sum(1 for c in clients if c.get("online"))
    out = [f"  clients: {total} ({online} online)"]
    for c in sorted(clients, key=lambda x: x.get("name", "")):
        name = c.get("name", "?")
        lf = c.get("lastbackup", 0) or 0
        issues = c.get("last_filebackup_issues", 0) or 0
        on = c.get("online")
        lf_h = (time.time() - lf) / 3600.0 if lf else 1e9
        ago = ("never" if not lf else f"{lf_h:.1f}h ago" if lf_h < 48 else f"{lf_h/24:.1f}d ago")
        flag = ""
        if lf == 0 or lf_h > 26:
            flag = "  <-- CHECK"
        elif issues:
            flag = f"  <-- {issues} issue(s)"
        elif not on:
            flag = "  <-- OFFLINE"
        out.append(f"    {name}: file {ago}{flag}")
    return "\n".join(out)


# ---------------- assemble ----------------
SECTIONS = [
    ("PROXMOX VMs", proxmox),
    ("DISK / STORAGE", disk),
    ("PBS BACKUPS (24h)", pbs),
    ("URBACKUP", urbackup),
    ("DOCKER HEALTH", docker),
    ("WAZUH AGENTS", wazuh),
    ("CROWDSEC", crowdsec),
    ("ADGUARD", adguard),
    ("UNIFI WAN", unifi),
    ("UPTIME KUMA", uptime_kuma),
]

def main():
    now = time.strftime("%a %Y-%m-%d %H:%M %Z")
    out = [f"Homelab Morning Briefing  -  {now}", "=" * 42]
    problems = 0
    for title, fn in SECTIONS:
        out.append(f"\n[{title}]")
        try:
            body = fn()
            out.append(body)
            if any(k in body for k in ("FAIL", "DOWN", "UNHEALTHY", "UNAVAILABLE",
                                       "CHECK", "LOW", "NO ACL")):
                problems += 1
        except Exception as e:
            out.append(f"  ERROR: {type(e).__name__}: {str(e)[:120]}")
            problems += 1
    head = "ALL GREEN" if problems == 0 else f"{problems} item(s) need attention"
    out.insert(1, head)
    print("\n".join(out))

if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, 'Homelab Morning Briefing', priority=4)
