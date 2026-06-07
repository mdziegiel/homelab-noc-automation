#!/usr/bin/env python3
"""
Homelab Homelab NOC Dashboard generator.
Collects all infra sources (stdlib only, per-source isolation) and renders a
single self-contained static HTML file (inline CSS + SVG, no external assets).
Run every 15 min via cron; served by a tiny http.server systemd unit on :8080.

Reuses the exact API patterns proven in morning_briefing.py and the report_*.py
cron scripts. One failed source never kills the page - it renders a degraded card.
"""
import base64, html, json, os, re, ssl, sys, time
import urllib.request, urllib.parse, http.cookiejar
from collections import Counter

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ENV_PATH = os.path.expanduser("~/.hermes/.env")
OUT_DIR = os.path.expanduser("~/homelab-dashboard")
OUT_FILE = os.path.join(OUT_DIR, "index.html")
TIMEOUT = 15
CERT_WARN_DAYS = 30
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def load_env(path):
    d = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r'^([A-Za-z_]\w*)=(.*)$', line.rstrip("\n"))
            if m:
                d[m.group(1)] = m.group(2)  # last-wins (dup blocks / stale placeholders)
    return d


E = load_env(ENV_PATH)

# ---------------------------------------------------------------------------
# Host resolution. Every infrastructure host is read from .env so this script
# is portable. Defaults below are SANITIZED example IPs (RFC1918 10.0.0.0/24) --
# replace them in your .env with your real hosts. See .env.template.
# ---------------------------------------------------------------------------
HOSTS = {
    "UNIFI_HOST":   E.get("UNIFI_HOST",   "10.0.0.1"),
    "ADGUARD_HOST": E.get("ADGUARD_HOST", "10.0.0.21"),
    "URBACKUP_HOST": E.get("URBACKUP_HOST", "10.0.0.76"),
    "PBS_HOST":     E.get("PBS_HOST",     "10.0.0.77"),
    "WAZUH_HOST":   E.get("WAZUH_HOST",   "10.0.0.233"),
    "HERMES_HOST":  E.get("HERMES_HOST",  "10.0.0.234"),
    "DOCKER_HOST_IP": E.get("DOCKER_HOST_IP", "10.0.0.237"),
    "PROXMOX_HOST": E.get("PROXMOX_HOST", "10.0.0.251"),
}
UNIFI_HOST = HOSTS["UNIFI_HOST"]
ADGUARD_HOST = HOSTS["ADGUARD_HOST"]
URBACKUP_HOST = HOSTS["URBACKUP_HOST"]
PBS_HOST = HOSTS["PBS_HOST"]
WAZUH_HOST = HOSTS["WAZUH_HOST"]
DOCKER_HOST_IP = HOSTS["DOCKER_HOST_IP"]
PROXMOX_HOST = HOSTS["PROXMOX_HOST"]


def _b64(s):
    return base64.b64encode(s.encode()).decode()


def req(url, headers=None, data=None, method=None, cookiejar=None):
    h = dict(headers or {})
    if isinstance(data, dict):
        data = json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
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


def _pmox_auth():
    tid = E.get("PROXMOX_TOKEN_ID", "")
    if "!" not in tid and "@pam" in tid:
        tid = tid.replace("@pam", "@pam!")
    sec = E.get("PROXMOX_TOKEN_SECRET", "")
    return {"Authorization": f"PVEAPIToken={tid}={sec}"}


# ============================ COLLECTORS ============================
# Each returns a dict. 'state' in {ok, warn, crit, degraded, error} drives color.

def collect_proxmox():
    d = {"state": "ok", "vms_running": 0, "vms_total": 0, "cpu": 0.0,
         "mem_used": 0.0, "mem_total": 0.0, "node": "?", "uptime_d": 0,
         "down_vms": [], "storage": []}
    auth = _pmox_auth()
    base = f"https://{PROXMOX_HOST}:8006/api2/json"
    nodes = jget(f"{base}/nodes", auth)["data"]
    node = None
    for n in nodes:
        node = n["node"]
        d["node"] = node
        d["cpu"] = round(n.get("cpu", 0) * 100, 1)
        d["mem_used"] = round(n.get("mem", 0) / 1e9, 1)
        d["mem_total"] = round(n.get("maxmem", 1) / 1e9, 1)
        d["uptime_d"] = int(n.get("uptime", 0)) // 86400
    vms = jget(f"{base}/nodes/{node}/qemu", auth)["data"]
    if vms:
        run = [v for v in vms if v.get("status") == "running"]
        d["vms_running"] = len(run)
        d["vms_total"] = len(vms)
        d["down_vms"] = sorted(
            f"{v['vmid']} {v.get('name','')}".strip()
            for v in vms if v.get("status") != "running")
        if d["down_vms"]:
            d["state"] = "warn"
    else:
        d["state"] = "degraded"
        d["note"] = "token has no ACL grant (0 VMs visible)"
    # storage
    st = jget(f"{base}/nodes/{node}/storage", auth)["data"]
    for s in st:
        if not s.get("total"):
            continue
        used, tot = s.get("used", 0), s.get("total", 1)
        pct = round(100 * used / tot, 1)
        d["storage"].append({"name": s["storage"], "pct": pct,
                             "used_g": round(used / 1e9, 1),
                             "total_g": round(tot / 1e9, 1)})
    d["storage"].sort(key=lambda x: -x["pct"])
    if any(s["pct"] > 85 for s in d["storage"]):
        d["state"] = "crit" if d["state"] != "degraded" else d["state"]
    return d


def collect_docker():
    d = {"state": "ok", "running": 0, "total": 0, "envs": 0, "bad": []}
    base = E.get("PORTAINER_URL", "").strip().rstrip("/")
    user = E.get("PORTAINER_USERNAME", "").strip()
    pw = E.get("PORTAINER_PASSWORD", "").strip()
    if not base or not user or not pw or pw.startswith("<"):
        return {"state": "degraded", "note": "Portainer creds not set", "running": 0, "total": 0}
    jwt = jget(f"{base}/api/auth", data={"Username": user, "Password": pw}, method="POST")["jwt"]
    auth = {"Authorization": f"Bearer {jwt}"}
    endpoints = jget(f"{base}/api/endpoints", auth)
    d["envs"] = len(endpoints)
    for ep in endpoints:
        epid = ep.get("Id")
        try:
            cs = jget(f"{base}/api/endpoints/{epid}/docker/containers/json?all=1", auth)
        except Exception as e:
            d["bad"].append(f"{ep.get('Name', epid)} unreachable: {type(e).__name__}")
            continue
        run = [c for c in cs if c.get("State") == "running"]
        d["running"] += len(run)
        d["total"] += len(cs)
        for c in cs:
            nm = c.get("Names", ["?"])[0].lstrip("/")
            if "unhealthy" in c.get("Status", "").lower():
                d["bad"].append(f"UNHEALTHY {nm}")
            elif c.get("State") != "running":
                d["bad"].append(f"down {nm}")
    if d["bad"]:
        d["state"] = "warn"
    return d


def collect_pbs():
    d = {"state": "ok", "ok": 0, "fail": 0, "run": 0, "last_backup": "?", "datastores": []}
    tk = jget(f"https://{PBS_HOST}:8007/api2/json/access/ticket",
              data=urllib.parse.urlencode({
                  "username": E.get("PBS_USERNAME", "root@pam"),
                  "password": E.get("PBS_PASSWORD", "")}),
              headers={"Content-Type": "application/x-www-form-urlencoded"},
              method="POST")["data"]["ticket"]
    cookie = {"Cookie": f"PBSAuthCookie={urllib.parse.quote(tk, safe='')}"}
    since = int(time.time()) - 86400
    tasks = jget(f"https://{PBS_HOST}:8007/api2/json/nodes/localhost/tasks"
                 f"?since={since}&limit=500", cookie)["data"]
    last_backup_epoch = 0
    for t in tasks:
        s = t.get("status", "running")
        wt = t.get("worker_type", "")
        if s == "running" or "endtime" not in t:
            d["run"] += 1
        elif s == "OK":
            d["ok"] += 1
            if wt == "backup" and t.get("endtime", 0) > last_backup_epoch:
                last_backup_epoch = t.get("endtime", 0)
        else:
            d["fail"] += 1
    if last_backup_epoch:
        ago_h = (time.time() - last_backup_epoch) / 3600
        d["last_backup"] = (f"{ago_h:.1f}h ago" if ago_h < 48
                            else f"{ago_h/24:.1f}d ago")
        if ago_h > 26:
            d["state"] = "warn"
    else:
        d["last_backup"] = "none in 24h"
        d["state"] = "warn"
    if d["fail"]:
        d["state"] = "crit"
    # datastore usage
    try:
        dss = jget(f"https://{PBS_HOST}:8007/api2/json/status/datastore-usage", cookie)["data"]
        for ds in dss:
            tot = ds.get("total", 0) or 0
            used = ds.get("used", 0) or 0
            pct = round(100 * used / tot, 1) if tot else 0
            d["datastores"].append({"name": ds.get("store", "?"), "pct": pct})
    except Exception:
        pass
    return d


def collect_uptime_kuma():
    d = {"state": "ok", "up": 0, "total": 0, "down": [], "other": [], "certs": []}
    base = E.get("UPTIME_KUMA_URL", "").strip().rstrip("/")
    key = E.get("UPTIME_KUMA_API_KEY", "").strip()
    if not base or not key or key.startswith("<"):
        return {"state": "degraded", "note": "Uptime Kuma key not set", "up": 0, "total": 0,
                "down": [], "other": [], "certs": []}
    auth = {"Authorization": "Basic " + _b64(f":{key}")}
    text = req(f"{base}/metrics", auth)
    status, cert_days, cert_valid = {}, {}, {}
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
        elif line.startswith("monitor_cert_days_remaining{"):
            cert_days[name] = val
        elif line.startswith("monitor_cert_is_valid{"):
            cert_valid[name] = val
    SMAP = {0: "DOWN", 1: "UP", 2: "PENDING", 3: "MAINT"}
    d["total"] = len(status)
    d["up"] = sum(1 for v in status.values() if v == 1)
    d["down"] = sorted(k for k, v in status.items() if v == 0)
    d["other"] = sorted([k, SMAP.get(v, str(v))] for k, v in status.items() if v not in (0, 1))
    for k, days in cert_days.items():
        valid = cert_valid.get(k, 1) == 1
        d["certs"].append({"name": k, "days": int(days), "valid": valid})
    d["certs"].sort(key=lambda x: x["days"])
    d["status_map"] = status
    if d["down"]:
        d["state"] = "crit"
    elif d["other"]:
        d["state"] = "warn"
    return d


def collect_crowdsec():
    d = {"state": "ok", "bans": 0, "local_bans": 0, "detections_24h": None, "top": []}
    apikey = E.get("CROWDSEC_API_KEY", "")
    dec = jget(f"http://{DOCKER_HOST_IP}:18080/v1/decisions", {"X-Api-Key": apikey})
    if isinstance(dec, list):
        d["bans"] = len(dec)
        local = [x for x in dec if x.get("origin") not in ("lists", "CAPI")]
        d["local_bans"] = len(local)
        scen = Counter(x.get("scenario", "?").split("/")[-1] for x in local)
        d["top"] = [[k, v] for k, v in scen.most_common(3) if k != "?"]
    # local detections 24h via watcher (creds usually empty -> stays None)
    mu = E.get("CROWDSEC_MACHINE_USER", "")
    mp = E.get("CROWDSEC_MACHINE_PASS", "")
    if mu and mp:
        try:
            tok = jget(f"http://{DOCKER_HOST_IP}:18080/v1/watchers/login",
                       {"Content-Type": "application/json"},
                       json.dumps({"machine_id": mu, "password": mp}).encode(), "POST")["token"]
            alerts = jget(f"http://{DOCKER_HOST_IP}:18080/v1/alerts?since=24h&limit=500",
                          {"Authorization": "Bearer " + tok})
            if isinstance(alerts, list):
                def is_local(a):
                    scope = (a.get("source", {}) or {}).get("scope", "") or ""
                    scen = a.get("scenario", "") or ""
                    return not scen.startswith("update :") and scope in ("Ip", "Range")
                d["detections_24h"] = sum(1 for a in alerts if is_local(a))
        except Exception:
            d["detections_24h"] = None
    return d


def collect_wazuh():
    d = {"state": "ok", "active": 0, "total": 0, "down": []}
    jwt = req(f"https://{WAZUH_HOST}:55000/security/user/authenticate?raw=true",
              {"Authorization": "Basic " + _b64(
                  f"{E.get('WAZUH_API_USER', 'YOUR_WAZUH_API_USER')}:{E.get('WAZUH_API_PASSWORD','')}")}).strip()
    ag = jget(f"https://{WAZUH_HOST}:55000/agents?limit=500",
              {"Authorization": f"Bearer {jwt}"})["data"]["affected_items"]
    d["total"] = len(ag)
    d["active"] = sum(1 for a in ag if a.get("status") == "active")
    d["down"] = [f"{a.get('id')} {a.get('name','')}".strip()
                 for a in ag if a.get("status") != "active"]
    if d["down"]:
        d["state"] = "warn"
    # alert volume from the indexer (last 24h). Manager API has no per-alert
    # severity; that lives only in wazuh-alerts-*. Degrade silently if missing.
    iu = E.get("WAZUH_INDEXER_USER", "").strip()
    ip = E.get("WAZUH_INDEXER_PASS", "").strip()
    if iu and ip:
        ix = E.get("WAZUH_INDEXER_HOST", f"https://{WAZUH_HOST}:9200").rstrip("/")
        try:
            q = {"size": 0,
                 "query": {"bool": {"filter": [
                     {"range": {"@timestamp": {"gte": "now-24h"}}}]}},
                 "aggs": {"hi": {"filter": {"range": {"rule.level": {"gte": 12}}}}}}
            res = jget(f"{ix}/wazuh-alerts-*/_search",
                       {"Authorization": "Basic " + _b64(f"{iu}:{ip}")}, data=q,
                       method="POST")
            tot = res.get("hits", {}).get("total", {})
            d["alerts_24h"] = tot.get("value", tot) if isinstance(tot, dict) else tot
            d["high_24h"] = res.get("aggregations", {}).get("hi", {}).get("doc_count", 0)
            if d["high_24h"]:
                d["state"] = "crit"
        except Exception as e:
            d["alerts_err"] = f"{type(e).__name__}"
    return d


def collect_unifi():
    d = {"state": "ok", "wan": "?", "wan_ip": "?", "clients": 0, "ips_24h": 0,
         "latency": None, "down_mbps": None, "up_mbps": None, "devices": [],
         "ssids": [], "month_rx": None, "month_tx": None, "month_total": None,
         "pia": None}
    GW = f"https://{UNIFI_HOST}"
    NET = GW + "/proxy/network/api/s/default"
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=CTX),
        urllib.request.HTTPCookieProcessor(cj))
    op.open(urllib.request.Request(
        f"{GW}/api/auth/login",
        data=json.dumps({"username": E.get("UNIFI_USERNAME", ""),
                         "password": E.get("UNIFI_PASSWORD", "")}).encode(),
        headers={"Content-Type": "application/json"}, method="POST"), timeout=TIMEOUT)
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

    def call(path, data=None, method="GET"):
        body = json.dumps(data).encode() if data is not None else None
        r = urllib.request.Request(NET + path, data=body, headers=hdr,
                                   method=("POST" if data is not None else method))
        return json.loads(op.open(r, timeout=TIMEOUT).read())

    health = call("/stat/health").get("data", [])
    wan = next((h for h in health if h.get("subsystem") == "wan"), {})
    www = next((h for h in health if h.get("subsystem") == "www"), {})
    d["wan"] = wan.get("status", "?")
    d["wan_ip"] = wan.get("wan_ip", "?")
    d["latency"] = www.get("latency")
    d["down_mbps"] = www.get("xput_down")
    d["up_mbps"] = www.get("xput_up")
    # clients = sum of num_user across lan + wlan subsystems
    clients = 0
    for h in health:
        if h.get("subsystem") in ("lan", "wlan"):
            clients += int(h.get("num_user", 0) or 0)
    d["clients"] = clients
    if d["wan"] != "ok":
        d["state"] = "crit"
    # IPS alarms 24h
    try:
        alarms = call("/list/alarm").get("data", [])
        cutoff = (time.time() - 86400) * 1000
        ips = [a for a in alarms
               if (a.get("time") or a.get("timestamp") or 0) >= cutoff
               and (a.get("key") == "EVT_IPS_IpsAlert" or a.get("inner_alert_signature"))]
        d["ips_24h"] = len(ips)
        if len(ips) > 0 and d["state"] == "ok":
            d["state"] = "warn"
    except Exception:
        d["ips_24h"] = 0
    # Network devices: UDM-SE, switches, APs (name + uptime)
    try:
        devs = call("/stat/device").get("data", [])
        TMAP = {"udm": "Gateway", "ugw": "Gateway", "usw": "Switch",
                "uap": "Access Point", "usg": "Gateway"}

        def fmt_uptime(s):
            s = int(s or 0)
            dd, hh = s // 86400, (s % 86400) // 3600
            if dd:
                return f"{dd}d {hh}h"
            mm = (s % 3600) // 60
            return f"{hh}h {mm}m"
        torder = {"udm": 0, "ugw": 0, "usg": 0, "usw": 1, "uap": 2}
        for dev in sorted(devs, key=lambda x: (torder.get(x.get("type"), 9),
                                               x.get("name", ""))):
            up = int(dev.get("uptime", 0) or 0)
            online = dev.get("state") == 1
            d["devices"].append({
                "name": dev.get("name", dev.get("model", "?")),
                "kind": TMAP.get(dev.get("type"), dev.get("type", "?")),
                "model": dev.get("model", "?"),
                "uptime": fmt_uptime(up) if online else "offline",
                "online": online})
            if not online:
                d["problems"] = d.get("problems", [])
                if d["state"] == "ok":
                    d["state"] = "warn"
    except Exception:
        pass

    # ---- WiFi clients per SSID (from active stations) ----
    try:
        sta = call("/stat/sta").get("data", [])
        ssid_ct = Counter()
        for c in sta:
            e = c.get("essid")
            if e:
                ssid_ct[e] += 1
        # Always surface the three networks Michael tracks, even at 0 clients
        WANTED = ["ZOMBIELAND5G", "ZOMBIELAND2G", "IOTNetwork"]
        seen = set()
        for name in WANTED:
            d["ssids"].append({"name": name, "clients": int(ssid_ct.get(name, 0))})
            seen.add(name)
        for name, ct in ssid_ct.most_common():
            if name not in seen:
                d["ssids"].append({"name": name, "clients": int(ct)})
    except Exception:
        pass

    # ---- Current-month WAN data usage ----
    try:
        rows = call("/stat/report/monthly.site",
                    {"attrs": ["wan-tx_bytes", "wan-rx_bytes", "time"], "n": 2},
                    "POST").get("data", [])
        if rows:
            cur = rows[-1]
            d["month_tx"] = cur.get("wan-tx_bytes")
            d["month_rx"] = cur.get("wan-rx_bytes")
            d["month_total"] = (cur.get("wan-tx_bytes", 0) or 0) + (cur.get("wan-rx_bytes", 0) or 0)
    except Exception:
        pass

    # ---- PIA VPN client status + uptime ----
    try:
        ncs = call("/rest/networkconf").get("data", [])
        pia = next((n for n in ncs
                    if n.get("purpose") == "vpn-client"
                    and "pia" in (n.get("name", "").lower())), None)
        if pia is None:
            pia = next((n for n in ncs if n.get("purpose") == "vpn-client"), None)
        if pia:
            status = pia.get("openvpn_configuration_status", "?")
            enabled = bool(pia.get("enabled"))
            connected = (str(status).upper() == "VALID") and enabled
            # The controller does not expose VPN-client uptime for a vpn-client
            # network (no uptime/up field on the gateway), so we report status only.
            d["pia"] = {"name": pia.get("name", "PIAVPN"), "status": str(status),
                        "enabled": enabled, "connected": connected, "uptime": "n/a"}
            if not connected and d["state"] == "ok":
                d["state"] = "warn"
    except Exception:
        pass
    return d


def collect_adguard():
    d = {"state": "ok", "queries": 0, "blocked": 0, "block_pct": 0.0, "avg_ms": 0.0}
    s = jget(f"http://{ADGUARD_HOST}/control/stats",
             {"Authorization": "Basic " + _b64(f"mdziegiel:{E.get('ADGUARD_PASSWORD','')}")})
    tot = s.get("num_dns_queries", 0)
    blk = s.get("num_blocked_filtering", 0)
    d["queries"] = tot
    d["blocked"] = blk
    d["block_pct"] = round(100 * blk / tot, 1) if tot else 0.0
    d["avg_ms"] = round(s.get("avg_processing_time", 0) * 1000, 1)
    return d


def collect_urbackup():
    """URBackup web API (salt/login/status). User is admin (URBACKUP_USERNAME)."""
    d = {"state": "ok", "total": 0, "online": 0, "clients": [], "problems": []}
    base = E.get("URBACKUP_URL", f"http://{URBACKUP_HOST}:55414").rstrip("/")
    user = E.get("URBACKUP_USERNAME", "admin")
    pw = E.get("URBACKUP_PASSWORD", "")
    if not pw or pw.startswith("<"):
        return {"state": "degraded", "note": "URBACKUP_PASSWORD not set",
                "total": 0, "online": 0, "clients": [], "problems": []}

    def api(action, body=""):
        url = base + "/x?a=" + action
        r = urllib.request.Request(url, data=body.encode(), method="POST",
                                   headers={"Content-Type": "application/json; charset=utf-8"})
        return json.loads(urllib.request.urlopen(r, timeout=TIMEOUT, context=CTX).read().decode("utf-8", "replace"))

    s = api("salt", "username=" + urllib.parse.quote(user))
    if s.get("error") == 1 or not s.get("salt"):
        raise RuntimeError("URBackup user not found")
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
        raise RuntimeError("URBackup login failed")
    ses = r3.get("session") or ses
    st = api("status", "ses=" + ses if ses else "")
    clients = st.get("status", [])
    d["total"] = len(clients)
    d["online"] = sum(1 for c in clients if c.get("online"))
    now = time.time()
    for c in sorted(clients, key=lambda x: x.get("name", "")):
        name = c.get("name", "?")
        lf = c.get("lastbackup", 0) or 0
        issues = c.get("last_filebackup_issues", 0) or 0
        on = bool(c.get("online"))
        lf_h = (now - lf) / 3600.0 if lf else 1e9
        ago = ("never" if not lf else
               f"{lf_h*60:.0f}m" if lf_h < 1 else
               f"{lf_h:.1f}h" if lf_h < 48 else f"{lf_h/24:.1f}d")
        cstate = "ok"
        if lf == 0:
            d["problems"].append(f"{name}: no file backup on record"); cstate = "crit"
        elif lf_h > 26:
            d["problems"].append(f"{name}: last backup {ago} ago (>26h)"); cstate = "warn"
        if issues:
            d["problems"].append(f"{name}: {issues} backup issue(s) last run")
            cstate = "warn" if cstate == "ok" else cstate
        if not on:
            d["problems"].append(f"{name}: client OFFLINE")
            cstate = "warn" if cstate == "ok" else cstate
        d["clients"].append({"name": name, "ago": ago, "online": on,
                             "issues": issues, "state": cstate})
    if any(c["state"] == "crit" for c in d["clients"]):
        d["state"] = "crit"
    elif d["problems"]:
        d["state"] = "warn"
    return d


def _qnap_text(el):
    return (el.text or "").strip() if el is not None else ""


def collect_qnap_one(ip, label):
    """One QNAP NAS: volumes, disk SMART health, system/cpu temp, fan, uptime."""
    import xml.etree.ElementTree as ET
    d = {"state": "ok", "label": label, "ip": ip, "host": "?", "model": "?",
         "cpu_temp": None, "sys_temp": None, "uptime_d": None, "fan_ok": True,
         "volumes": [], "disks": [], "problems": []}
    user = E.get("QNAP_USERNAME", "admin")
    pw = E.get("QNAP_PASSWORD", "")
    if not ip or not pw:
        return {"state": "degraded", "label": label, "ip": ip or "?",
                "note": "QNAP creds not set", "volumes": [], "disks": [], "problems": []}
    # auth
    aurl = f"https://{ip}/cgi-bin/authLogin.cgi"
    adata = urllib.parse.urlencode({"user": user, "pwd": _b64(pw)}).encode()
    abody = urllib.request.urlopen(urllib.request.Request(aurl, data=adata),
                                   timeout=TIMEOUT, context=CTX).read().decode("utf-8", "replace")
    m = re.search(r"<authSid><!\[CDATA\[(.*?)\]\]></authSid>", abody) or re.search(r"<authSid>(.*?)</authSid>", abody)
    sid = m.group(1) if m else ""
    if not sid:
        raise RuntimeError("QNAP auth failed (no sid)")

    def get(path):
        return urllib.request.urlopen(f"https://{ip}{path}", timeout=TIMEOUT, context=CTX).read().decode("utf-8", "replace")

    # ----- sysinfo: temps, fan, uptime, hostname -----
    si = ET.fromstring(get(f"/cgi-bin/management/manaRequest.cgi?subfunc=sysinfo&sid={sid}"))
    def sif(tag):
        e = si.find(".//" + tag)
        return _qnap_text(e)
    d["host"] = sif("hostname") or "?"
    d["model"] = sif("displayModelName") or "?"
    try:
        d["cpu_temp"] = int(sif("cpu_tempc"))
    except (ValueError, TypeError):
        pass
    try:
        d["sys_temp"] = int(sif("sys_tempc"))
    except (ValueError, TypeError):
        pass
    try:
        d["uptime_d"] = int(sif("uptime_day"))
    except (ValueError, TypeError):
        pass
    # fan: any sysfan*_stat != 0 or sysfan_fail* == 1 => fault
    fan_ok = True
    for k in range(1, 6):
        st = si.find(f".//sysfan{k}_stat")
        fl = si.find(f".//sysfan_fail{k}")
        if st is not None and _qnap_text(st) not in ("0", ""):
            fan_ok = False
        if fl is not None and _qnap_text(fl) == "1":
            fan_ok = False
    d["fan_ok"] = fan_ok
    if not fan_ok:
        d["problems"].append("fan fault")
    # temp thresholds (from device): SysTempWarnT etc.; use sane fallbacks
    try:
        sys_warn = int(sif("SysTempWarnT") or 60)
    except ValueError:
        sys_warn = 60
    if d["sys_temp"] is not None and d["sys_temp"] >= sys_warn:
        d["problems"].append(f"system temp {d['sys_temp']}C >= {sys_warn}C")
        d["state"] = "warn"

    # ----- volume usage -----
    vu = ET.fromstring(get(f"/cgi-bin/management/chartReq.cgi?chart_func=disk_usage&disk_select=all&include=all&sid={sid}"))
    labels = {}
    for vol in vu.findall(".//volumeList/volume"):
        vv = _qnap_text(vol.find("volumeValue"))
        labels[vv] = _qnap_text(vol.find("volumeLabel")) or ("Vol " + vv)
        vstat = _qnap_text(vol.find("volumeStatus"))
        if vstat not in ("0", "", "Ready"):
            d["problems"].append(f"volume {labels[vv]} status={vstat}")
    for vu_el in vu.findall(".//volumeUseList/volumeUse"):
        vv = _qnap_text(vu_el.find("volumeValue"))
        try:
            tot = int(_qnap_text(vu_el.find("total_size")) or 0)
            free = int(_qnap_text(vu_el.find("free_size")) or 0)
        except ValueError:
            continue
        if not tot:
            continue
        used = tot - free
        pct = round(100 * used / tot, 1)
        nm = labels.get(vv, "Vol " + vv)
        d["volumes"].append({"name": nm, "pct": pct,
                             "used_t": round(used / 1e12, 2), "total_t": round(tot / 1e12, 2)})
        if pct > 90:
            d["problems"].append(f"volume {nm} {pct:.0f}% full")
            d["state"] = "crit"
        elif pct > 85 and d["state"] == "ok":
            d["state"] = "warn"
    d["volumes"].sort(key=lambda x: -x["pct"])

    # ----- disk SMART health -----
    dh = ET.fromstring(get(f"/cgi-bin/disk/qsmart.cgi?func=all_hd_data&sid={sid}"))
    for e in dh.findall(".//Disk_Info/entry"):
        alias = _qnap_text(e.find("Disk_Alias"))
        health = _qnap_text(e.find("Health"))
        dstat = _qnap_text(e.find("Disk_Status"))
        tc = _qnap_text(e.find("Temperature/oC"))
        try:
            tc = int(tc)
        except ValueError:
            tc = None
        # Skip empty bays: QTS reports unpopulated slots with Disk_Status == -5,
        # no temperature, and a bare "SATA N" alias (no HDD/SSD designation).
        if dstat == "-5" and tc is None:
            continue
        d["disks"].append({"alias": alias, "health": health or "?",
                          "status": dstat, "temp": tc})
        if health and health.upper() not in ("OK", "GOOD", "NORMAL", ""):
            d["problems"].append(f"disk {alias} health={health}")
            d["state"] = "crit"
        elif dstat not in ("0", "", "Ready", "ready"):
            # Disk_Status 0 = good on QTS; any other non-empty status on a
            # populated disk is worth a warning.
            d["problems"].append(f"disk {alias} status={dstat}")
            if d["state"] != "crit":
                d["state"] = "warn"
    return d


def collect_qnaps():
    """Aggregate wrapper: returns a dict of per-unit results keyed q1/q2/q3."""
    units = [("QNAP1", E.get("QNAP1_HOST")), ("QNAP2", E.get("QNAP2_HOST")),
             ("QNAP3", E.get("QNAP3_HOST"))]
    out = {"state": "ok", "units": []}
    worst = "ok"
    order = ["ok", "degraded", "warn", "crit", "error"]
    for label, ip in units:
        try:
            r = collect_qnap_one(ip, label)
        except Exception as e:
            r = {"state": "error", "label": label, "ip": ip or "?",
                 "error": f"{type(e).__name__}: {str(e)[:100]}",
                 "volumes": [], "disks": [], "problems": []}
        out["units"].append(r)
        if order.index(r.get("state", "error")) > order.index(worst):
            worst = r.get("state", "error")
    out["state"] = worst
    return out


def collect_homeassistant():
    """Home Assistant: entity count + active alerts / unavailable entities."""
    d = {"state": "ok", "entities": 0, "alerts_on": 0, "notifications": 0,
         "unavailable": 0, "alert_names": [], "domains": 0}
    base = E.get("HASS_URL", "").rstrip("/")
    tok = E.get("HASS_TOKEN", "")
    if not base or not tok or tok.startswith("<"):
        return {"state": "degraded", "note": "HASS_URL/HASS_TOKEN not set",
                "entities": 0, "alerts_on": 0, "notifications": 0,
                "unavailable": 0, "alert_names": []}
    states = jget(base + "/api/states", {"Authorization": "Bearer " + tok})
    d["entities"] = len(states)
    d["domains"] = len(set(e["entity_id"].split(".")[0] for e in states))
    on_alerts = [e for e in states if e["entity_id"].startswith("alert.") and e.get("state") == "on"]
    notes = [e for e in states if e["entity_id"].startswith("persistent_notification.")]
    unavail = [e for e in states if e.get("state") in ("unavailable", "unknown")]
    d["alerts_on"] = len(on_alerts)
    d["notifications"] = len(notes)
    d["unavailable"] = len(unavail)
    d["alert_names"] = sorted(
        (e.get("attributes", {}).get("friendly_name") or e["entity_id"]) for e in on_alerts)[:6]
    if on_alerts:
        d["state"] = "crit"
    elif notes:
        d["state"] = "warn"
    return d


# ============================ MEDIA STACK COLLECTORS ============================
UA_BROWSER = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def _arr_base(prefix):
    base = E.get(prefix + "_URL", "").strip().rstrip("/")
    key = E.get(prefix + "_API_KEY", "").strip()
    return base, key


def collect_sonarr():
    base, key = _arr_base("SONARR")
    if not base or not key:
        return {"state": "degraded", "note": "SONARR not configured"}
    h = {"X-Api-Key": key}
    series = jget(f"{base}/api/v3/series", h)
    monitored = sum(1 for s in series if s.get("monitored"))
    queue = jget(f"{base}/api/v3/queue?page=1&pageSize=1", h).get("totalRecords", 0)
    missing = jget(f"{base}/api/v3/wanted/missing?page=1&pageSize=1", h).get("totalRecords", 0)
    state = "warn" if (queue > 0 or missing > 0) else "ok"
    return {"state": state, "total": len(series), "monitored": monitored,
            "queue": queue, "missing": missing}


def collect_radarr():
    base, key = _arr_base("RADARR")
    if not base or not key:
        return {"state": "degraded", "note": "RADARR not configured"}
    h = {"X-Api-Key": key}
    movies = jget(f"{base}/api/v3/movie", h)
    monitored = sum(1 for m in movies if m.get("monitored"))
    queue = jget(f"{base}/api/v3/queue?page=1&pageSize=1", h).get("totalRecords", 0)
    missing = jget(f"{base}/api/v3/wanted/missing?page=1&pageSize=1", h).get("totalRecords", 0)
    state = "warn" if (queue > 0 or missing > 0) else "ok"
    return {"state": state, "total": len(movies), "monitored": monitored,
            "queue": queue, "missing": missing}


def collect_prowlarr():
    base, key = _arr_base("PROWLARR")
    if not base or not key:
        return {"state": "degraded", "note": "PROWLARR not configured"}
    h = {"X-Api-Key": key}
    idx = jget(f"{base}/api/v1/indexer", h)
    enabled = sum(1 for i in idx if i.get("enable"))
    # indexerstatus lists indexers currently in a failed/back-off state
    try:
        failing = len(jget(f"{base}/api/v1/indexerstatus", h))
    except Exception:
        failing = 0
    healthy = enabled - failing
    state = "warn" if failing else "ok"
    return {"state": state, "total": len(idx), "enabled": enabled,
            "healthy": max(healthy, 0), "failing": failing}


def collect_sabnzbd():
    base = E.get("SABNZBD_URL", "").strip().rstrip("/")
    key = E.get("SABNZBD_API_KEY", "").strip()
    if not base or not key:
        return {"state": "degraded", "note": "SABNZBD not configured"}
    q = jget(f"{base}/api?mode=queue&output=json&apikey={key}").get("queue", {})
    try:
        slots = int(q.get("noofslots", 0))
    except (TypeError, ValueError):
        slots = 0
    try:
        kbps = float(q.get("kbpersec", 0) or 0)
    except (TypeError, ValueError):
        kbps = 0.0
    speed_mbps = round(kbps / 1024, 1)
    status = q.get("status", "Idle")
    mbleft = q.get("mbleft", "0")
    timeleft = q.get("timeleft", "0:00:00")
    # daily total
    day_bytes = 0
    try:
        srv = jget(f"{base}/api?mode=server_stats&output=json&apikey={key}")
        day_bytes = int(srv.get("day", 0) or 0)
    except Exception:
        pass
    day_gb = round(day_bytes / (1024 ** 3), 2)
    state = "warn" if status.lower() in ("paused",) else "ok"
    return {"state": state, "slots": slots, "speed_mbps": speed_mbps,
            "status": status, "mbleft": mbleft, "timeleft": timeleft,
            "day_gb": day_gb}


def collect_overseerr():
    base = E.get("OVERSEERR_URL", "").strip().rstrip("/")
    key = E.get("OVERSEERR_API_KEY", "").strip()
    if not base or not key:
        return {"state": "degraded", "note": "OVERSEERR not configured"}
    h = {"X-Api-Key": key, "User-Agent": UA_BROWSER, "Accept": "application/json"}
    # Primary is the local IP (set in .env). If that fails, fall back to the
    # public domain so a container/IP change still has a chance. The 403 seen
    # historically was a TRUNCATED api key, not auth scheme / Cloudflare.
    candidates = [base]
    dom = "https://overseerr.homelab.me"
    if dom != base:
        candidates.append(dom)
    last_err = None
    for url in candidates:
        try:
            c = jget(f"{url}/api/v1/request/count", h)
            pending = c.get("pending", 0)
            state = "warn" if pending else "ok"
            return {"state": state, "pending": pending,
                    "approved": c.get("approved", 0), "available": c.get("available", 0),
                    "processing": c.get("processing", 0), "total": c.get("total", 0)}
        except Exception as e:
            last_err = e
            continue
    raise last_err


def collect_tautulli():
    base = E.get("TAUTULLI_URL", "").strip().rstrip("/")
    key = E.get("TAUTULLI_API_KEY", "").strip()
    if not base or not key:
        return {"state": "degraded", "note": "TAUTULLI not configured"}
    act = jget(f"{base}/api/v2?apikey={key}&cmd=get_activity"
               ).get("response", {}).get("data", {})
    streams = act.get("stream_count", 0)
    try:
        streams = int(streams)
    except (TypeError, ValueError):
        streams = 0
    # plays today
    pbd = jget(f"{base}/api/v2?apikey={key}&cmd=get_plays_by_date&time_range=1"
               ).get("response", {}).get("data", {})
    plays_today = 0
    for s in pbd.get("series", []):
        if s.get("name") == "Total":
            plays_today = sum(int(x or 0) for x in (s.get("data") or []))
    # most active user today
    top_user, top_plays = None, 0
    hs = jget(f"{base}/api/v2?apikey={key}&cmd=get_home_stats&time_range=1&stats_count=5"
              ).get("response", {}).get("data", [])
    for sec in hs:
        if sec.get("stat_id") == "top_users":
            rows = sec.get("rows", [])
            if rows:
                top_user = rows[0].get("friendly_name") or rows[0].get("user")
                top_plays = rows[0].get("total_plays", 0)
            break
    return {"state": "ok", "streams": streams, "plays_today": plays_today,
            "top_user": top_user, "top_plays": top_plays}


def collect_plex():
    base = E.get("PLEX_URL", "").strip().rstrip("/")
    tok = E.get("PLEX_TOKEN", "").strip()
    if not base or not tok:
        return {"state": "degraded", "note": "PLEX not configured"}
    h = {"X-Plex-Token": tok, "Accept": "application/json"}
    sess = jget(f"{base}/status/sessions", h).get("MediaContainer", {})
    streams = sess.get("size", 0)
    try:
        streams = int(streams)
    except (TypeError, ValueError):
        streams = 0
    libs = jget(f"{base}/library/sections", h).get("MediaContainer", {}).get("Directory", [])
    movies = shows = 0
    for d in libs:
        k, t = d.get("key"), d.get("type")
        try:
            mc = jget(f"{base}/library/sections/{k}/all"
                      f"?X-Plex-Container-Start=0&X-Plex-Container-Size=0", h
                      ).get("MediaContainer", {})
            sz = mc.get("totalSize", mc.get("size", 0)) or 0
            sz = int(sz)
        except Exception:
            sz = 0
        if t == "movie":
            movies += sz
        elif t == "show":
            shows += sz
    return {"state": "ok", "streams": streams, "movies": movies, "shows": shows}


def collect_adguard2():
    base = E.get("ADGUARD2_URL", "").strip().rstrip("/")
    user = E.get("ADGUARD2_USERNAME", "").strip()
    pw = E.get("ADGUARD2_PASSWORD", "").strip()
    if not base or not user:
        return {"state": "degraded", "note": "ADGUARD2 not configured"}
    d = {"state": "ok", "queries": 0, "blocked": 0, "block_pct": 0.0, "avg_ms": 0.0}
    s = jget(f"{base}/control/stats",
             {"Authorization": "Basic " + _b64(f"{user}:{pw}")})
    tot = s.get("num_dns_queries", 0)
    blk = s.get("num_blocked_filtering", 0)
    d["queries"] = tot
    d["blocked"] = blk
    d["block_pct"] = round(100 * blk / tot, 1) if tot else 0.0
    d["avg_ms"] = round(s.get("avg_processing_time", 0) * 1000, 1)
    return d


def _human_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024 or unit == "PB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024


def collect_cloudflare():
    """Cloudflare GraphQL Analytics. requests/threats/bandwidth today (1dGroups)
    + WAF events / blocked-IP counts last 24h (firewallEventsAdaptiveGroups).
    The firewall dataset needs the token's Firewall/Analytics scope on the zone;
    if it's not granted the API returns an authz error - we degrade that one
    line to a note rather than failing the whole card."""
    import datetime as _dt
    token = E.get("CLOUDFLARE_TOKEN", "").strip()
    zone = E.get("CLOUDFLARE_ZONE_ID", "").strip()
    if not token or not zone or token.startswith("<"):
        return {"state": "degraded", "note": "Cloudflare token/zone not set",
                "requests": 0, "threats": 0, "bytes": 0, "waf": None}
    d = {"state": "ok", "requests": 0, "threats": 0, "bytes": 0,
         "waf_events": None, "waf_blocked": None, "waf_note": None}
    api = "https://api.cloudflare.com/client/v4/graphql"
    auth = {"Authorization": f"Bearer {token}"}
    today = _dt.date.today().isoformat()
    dt24 = (_dt.datetime.now(_dt.UTC) - _dt.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    # --- HTTP analytics (today) ---
    q1 = ("query($z:String!,$d:String!){viewer{zones(filter:{zoneTag:$z}){"
          "httpRequests1dGroups(limit:1,filter:{date_geq:$d}){"
          "sum{requests bytes threats}}}}}")
    r1 = jget(api, auth, {"query": q1, "variables": {"z": zone, "d": today}}, "POST")
    if r1.get("errors"):
        raise RuntimeError("CF http analytics: " + str(r1["errors"][0].get("message", ""))[:120])
    grp = r1["data"]["viewer"]["zones"][0]["httpRequests1dGroups"]
    if grp:
        s = grp[0]["sum"]
        d["requests"] = s.get("requests", 0)
        d["threats"] = s.get("threats", 0)
        d["bytes"] = s.get("bytes", 0)
    if d["threats"]:
        d["state"] = "warn"
    # --- WAF / firewall events (24h), best-effort ---
    q2 = ("query($z:String!,$d:Time!){viewer{zones(filter:{zoneTag:$z}){"
          "all:firewallEventsAdaptiveGroups(limit:1,filter:{datetime_geq:$d}){count}"
          "blk:firewallEventsAdaptiveGroups(limit:1,filter:{datetime_geq:$d,action:\"block\"}){count}"
          "}}}")
    try:
        r2 = jget(api, auth, {"query": q2, "variables": {"z": zone, "d": dt24}}, "POST")
        if r2.get("errors"):
            msg = str(r2["errors"][0].get("message", ""))
            if "does not have access" in msg or "authz" in msg.lower():
                # HTTP analytics above succeeded with this same token, so the
                # token DOES have Analytics Read. firewallEventsAdaptiveGroups is
                # a Pro+ dataset - on a Free zone it returns this authz error
                # regardless of token scope. Not fixable by re-scoping the token.
                d["waf_note"] = "WAF analytics needs Pro plan (Free zone)"
            else:
                d["waf_note"] = msg[:60]
        else:
            z = r2["data"]["viewer"]["zones"][0]
            d["waf_events"] = (z.get("all") or [{}])[0].get("count", 0)
            d["waf_blocked"] = (z.get("blk") or [{}])[0].get("count", 0)
            if d["waf_blocked"] and d["state"] == "ok":
                d["state"] = "warn"
    except Exception as e:
        d["waf_note"] = f"WAF query failed: {type(e).__name__}"
    return d


def collect_npm():
    """Nginx Proxy Manager. POST /api/tokens -> JWT, then proxy-hosts +
    certificates. Flags hosts that are disabled or report an nginx error."""
    base = E.get("NPM_URL", "").strip().rstrip("/")
    email = E.get("NPM_EMAIL", "").strip()
    pw = E.get("NPM_PASSWORD", "").strip()
    if not base or not email or not pw or pw.startswith("<"):
        return {"state": "degraded", "note": "NPM creds not set",
                "hosts": 0, "enabled": 0, "disabled": 0, "certs": 0, "problems": []}
    d = {"state": "ok", "hosts": 0, "enabled": 0, "disabled": 0,
         "errored": 0, "certs": 0, "certs_expiring": 0, "problems": []}
    tok = jget(f"{base}/api/tokens",
               data={"identity": email, "secret": pw}, method="POST").get("token")
    if not tok:
        raise RuntimeError("NPM auth returned no token")
    auth = {"Authorization": f"Bearer {tok}"}
    hosts = jget(f"{base}/api/nginx/proxy-hosts", auth)
    d["hosts"] = len(hosts)
    for h in hosts:
        nm = (h.get("domain_names") or ["?"])[0]
        if not h.get("enabled"):
            d["disabled"] += 1
            d["problems"].append(f"disabled: {nm}")
        else:
            d["enabled"] += 1
        meta = h.get("meta") or {}
        if meta.get("nginx_online") is False or meta.get("nginx_err"):
            d["errored"] += 1
            err = str(meta.get("nginx_err") or "offline")[:50]
            d["problems"].append(f"ERROR {nm}: {err}")
    # certificates
    try:
        certs = jget(f"{base}/api/nginx/certificates", auth)
        d["certs"] = len(certs)
        now = time.time()
        for c in certs:
            exp = c.get("expires_on")
            if not exp:
                continue
            try:
                ep = time.mktime(time.strptime(exp[:19], "%Y-%m-%dT%H:%M:%S"))
                if (ep - now) / 86400 <= 14:
                    d["certs_expiring"] += 1
                    d["problems"].append(
                        f"cert expiring: {(c.get('nice_name') or c.get('domain_names',['?'])[0])}")
            except Exception:
                pass
    except Exception:
        pass
    if d["errored"]:
        d["state"] = "crit"
    elif d["disabled"] or d["certs_expiring"]:
        d["state"] = "warn"
    return d


def collect_tailscale():
    """Tailscale tailnet devices via the v2 API. The v2 /devices endpoint does
    NOT return a live `online` boolean, so we derive online from lastSeen
    recency (<5 min = online). Also surfaces exit-node advertisers and the
    soonest non-disabled key expiry."""
    import datetime as _dt
    token = E.get("TAILSCALE_API_KEY", "").strip()
    if not token or token.startswith("<"):
        return {"state": "degraded", "note": "Tailscale API key not set",
                "total": 0, "online": 0, "devices": []}
    d = {"state": "ok", "total": 0, "online": 0, "offline": 0,
         "exit_nodes": [], "devices": [], "soonest_expiry_days": None}
    j = jget("https://api.tailscale.com/api/v2/tailnet/-/devices",
             {"Authorization": f"Bearer {token}"})
    devs = j.get("devices", [])
    d["total"] = len(devs)
    now = _dt.datetime.now(_dt.UTC)
    soonest = None
    for dev in devs:
        ls = dev.get("lastSeen", "")
        online = False
        if ls:
            try:
                t = _dt.datetime.strptime(ls, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.UTC)
                online = (now - t).total_seconds() < 300
            except Exception:
                pass
        if online:
            d["online"] += 1
        else:
            d["offline"] += 1
        # exit node advertised?
        if dev.get("exitNodeOption"):
            d["exit_nodes"].append(dev.get("hostname", "?"))
        # key expiry (skip devices with expiry disabled)
        if not dev.get("keyExpiryDisabled") and dev.get("expires"):
            try:
                ex = _dt.datetime.strptime(dev["expires"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.UTC)
                days = (ex - now).total_seconds() / 86400
                if days > -3650 and (soonest is None or days < soonest):
                    soonest = days
            except Exception:
                pass
        d["devices"].append({
            "name": dev.get("hostname", dev.get("name", "?")),
            "os": dev.get("os", "?"),
            "online": online,
            "exit_node": bool(dev.get("exitNodeOption")),
        })
    d["devices"].sort(key=lambda x: (not x["online"], x["name"].lower()))
    if soonest is not None:
        d["soonest_expiry_days"] = int(soonest)
    return d


def collect_wgdashboard():
    """WGDashboard. Real auth flow is POST /api/authenticate (cookie jar) then
    GET /api/getWireguardConfigurations. Each config returns ConnectedPeers,
    TotalPeers and Status (True = interface up). Aggregates across all configs."""
    base = E.get("WGDASHBOARD_URL", "").strip().rstrip("/")
    user = E.get("WGDASHBOARD_USERNAME", "").strip()
    pw = E.get("WGDASHBOARD_PASSWORD", "").strip()
    if not base or not user or not pw or pw.startswith("<"):
        return {"state": "degraded", "note": "WGDashboard creds not set",
                "connected": 0, "total_peers": 0, "interfaces": []}
    d = {"state": "ok", "connected": 0, "total_peers": 0,
         "ifaces_up": 0, "ifaces_total": 0, "interfaces": []}
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=CTX),
        urllib.request.HTTPCookieProcessor(cj))

    def call(path, data=None, method="GET"):
        h = {}
        if isinstance(data, dict):
            data = json.dumps(data).encode()
            h["Content-Type"] = "application/json"
        r = urllib.request.Request(base + path, data=data, headers=h, method=method)
        return json.loads(op.open(r, timeout=TIMEOUT).read().decode("utf-8", "replace"))

    auth = call("/api/authenticate", {"username": user, "password": pw}, "POST")
    if not auth.get("status"):
        raise RuntimeError("WGDashboard auth failed: " + str(auth.get("message"))[:80])
    confs = call("/api/getWireguardConfigurations").get("data", [])
    d["ifaces_total"] = len(confs)
    for c in confs:
        up = bool(c.get("Status"))
        cp = int(c.get("ConnectedPeers", 0) or 0)
        tp = int(c.get("TotalPeers", 0) or 0)
        d["connected"] += cp
        d["total_peers"] += tp
        if up:
            d["ifaces_up"] += 1
        d["interfaces"].append({"name": c.get("Name", "?"), "up": up,
                                "connected": cp, "total": tp,
                                "addr": c.get("Address", "?")})
    d["interfaces"].sort(key=lambda x: x["name"])
    if d["ifaces_total"] and d["ifaces_up"] < d["ifaces_total"]:
        d["state"] = "warn"
    return d


SOURCES = [
    ("proxmox", collect_proxmox),
    ("docker", collect_docker),
    ("pbs", collect_pbs),
    ("kuma", collect_uptime_kuma),
    ("crowdsec", collect_crowdsec),
    ("wazuh", collect_wazuh),
    ("unifi", collect_unifi),
    ("adguard", collect_adguard),
    ("urbackup", collect_urbackup),
    ("qnap", collect_qnaps),
    ("homeassistant", collect_homeassistant),
    ("adguard2", collect_adguard2),
    ("cloudflare", collect_cloudflare),
    ("npm", collect_npm),
    ("tailscale", collect_tailscale),
    ("wgdashboard", collect_wgdashboard),
    ("plex", collect_plex),
    ("tautulli", collect_tautulli),
    ("sonarr", collect_sonarr),
    ("radarr", collect_radarr),
    ("sabnzbd", collect_sabnzbd),
    ("overseerr", collect_overseerr),
    ("prowlarr", collect_prowlarr),
]


def gather():
    data = {}
    for key, fn in SOURCES:
        try:
            data[key] = fn()
        except Exception as e:
            data[key] = {"state": "error",
                         "error": f"{type(e).__name__}: {str(e)[:140]}"}
    return data


# ============================ TREND / HISTORY STORAGE ============================
STATE_DIR = os.path.expanduser("~/.hermes/state")
TRENDS_FILE = os.path.join(STATE_DIR, "dashboard_trends.json")
KUMA_HIST_HOURS = 24
DAILY_KEEP = 30


def load_trends():
    try:
        with open(TRENDS_FILE, encoding="utf-8") as f:
            t = json.load(f)
    except Exception:
        t = {}
    t.setdefault("daily", {})          # {"YYYY-MM-DD": {metric: value}}
    t.setdefault("kuma_history", {})   # {"monitor": [[epoch, status], ...]}
    return t


def update_trends(data, now_epoch):
    """Record a daily snapshot (latest-wins) for CrowdSec/AdGuard and append a
    Kuma per-monitor status sample. Prune to retention windows. Returns the
    updated trends dict (also persisted atomically)."""
    t = load_trends()
    day = time.strftime("%Y-%m-%d", time.localtime(now_epoch))

    C = data.get("crowdsec", {})
    A = data.get("adguard", {})
    rec = t["daily"].get(day, {})
    if C.get("state") != "error":
        rec["crowdsec_bans"] = C.get("bans", rec.get("crowdsec_bans", 0))
        rec["crowdsec_local"] = C.get("local_bans", rec.get("crowdsec_local", 0))
    if A.get("state") != "error":
        rec["adguard_blocked"] = A.get("blocked", rec.get("adguard_blocked", 0))
        rec["adguard_queries"] = A.get("queries", rec.get("adguard_queries", 0))
        rec["adguard_block_pct"] = A.get("block_pct", rec.get("adguard_block_pct", 0))
    A2 = data.get("adguard2", {})
    if A2.get("state") not in ("error", "degraded"):
        rec["adguard2_blocked"] = A2.get("blocked", rec.get("adguard2_blocked", 0))
        rec["adguard2_queries"] = A2.get("queries", rec.get("adguard2_queries", 0))
        rec["adguard2_block_pct"] = A2.get("block_pct", rec.get("adguard2_block_pct", 0))
    t["daily"][day] = rec
    # prune daily
    for k in sorted(t["daily"].keys())[:-DAILY_KEEP]:
        del t["daily"][k]

    # Kuma history: append current status per monitor, keep last 24h
    K = data.get("kuma", {})
    if K.get("state") != "error" and (K.get("up") or K.get("total")):
        # rebuild status map from down/other + total: easier to store explicitly
        statuses = K.get("status_map")
        if statuses:
            cutoff = now_epoch - KUMA_HIST_HOURS * 3600
            for name, val in statuses.items():
                hist = t["kuma_history"].setdefault(name, [])
                hist.append([int(now_epoch), int(val)])
                t["kuma_history"][name] = [h for h in hist if h[0] >= cutoff]
            # drop monitors no longer present
            for gone in [m for m in t["kuma_history"] if m not in statuses]:
                t["kuma_history"][gone] = [h for h in t["kuma_history"][gone]
                                           if h[0] >= now_epoch - KUMA_HIST_HOURS * 3600]
                if not t["kuma_history"][gone]:
                    del t["kuma_history"][gone]

    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = TRENDS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(t, f)
    os.replace(tmp, TRENDS_FILE)
    return t


# ============================ RENDER ============================

def esc(x):
    return html.escape(str(x))


def pct_color(p):
    if p > 85:
        return "crit"
    if p >= 75:
        return "warn"
    return "ok"


def donut(name, pct):
    """Inline SVG donut gauge."""
    cls = pct_color(pct)
    r = 52
    circ = 2 * 3.14159265 * r
    dash = circ * min(pct, 100) / 100
    return f"""<div class="gauge">
      <svg viewBox="0 0 140 140" class="g-{cls}">
        <circle cx="70" cy="70" r="{r}" class="g-track"/>
        <circle cx="70" cy="70" r="{r}" class="g-val"
                stroke-dasharray="{dash:.1f} {circ:.1f}"
                transform="rotate(-90 70 70)"/>
        <text x="70" y="64" class="g-pct">{pct:.0f}%</text>
        <text x="70" y="86" class="g-lbl">{esc(name)[:14]}</text>
      </svg>
    </div>"""


def card(title, badge_state, body_html, sub=""):
    sub_html = f'<div class="sub">{sub}</div>' if sub else ""
    return f"""<div class="card s-{badge_state}">
      <div class="card-h"><span class="dot"></span><h3>{esc(title)}</h3></div>
      <div class="card-b">{body_html}</div>{sub_html}
    </div>"""


def metric(label, value, state=""):
    sc = f" m-{state}" if state else ""
    return f'<div class="metric{sc}"><div class="m-v">{value}</div><div class="m-l">{esc(label)}</div></div>'


def _hb(n):
    """Human-readable bytes."""
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024 or u == "PB":
            return f"{n:.1f}{u}" if u != "B" else f"{int(n)}B"
        n /= 1024


def _hb_short(n):
    """Compact bytes for tight card metrics: single-letter unit, no decimals
    for values >=100, one decimal below. e.g. 470600000000 -> '438G'."""
    n = float(n or 0)
    for u in ("B", "K", "M", "G", "T", "P"):
        if n < 1024 or u == "P":
            if u == "B":
                return f"{int(n)}B"
            return f"{n:.0f}{u}" if n >= 100 else f"{n:.1f}{u}"
        n /= 1024


def sparkline(values, width=140, height=34, state="ok"):
    """Inline SVG sparkline from a list of numbers."""
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return '<div class="spark-empty">collecting trend data&hellip;</div>'
    lo, hi = min(vals), max(vals)
    rng = (hi - lo) or 1
    n = len(vals)
    step = width / (n - 1)
    pts = []
    for i, v in enumerate(vals):
        x = i * step
        y = height - 4 - (v - lo) / rng * (height - 8)
        pts.append(f"{x:.1f},{y:.1f}")
    poly = " ".join(pts)
    last_x, last_y = pts[-1].split(",")
    area = f"0,{height} " + poly + f" {width},{height}"
    return (f'<svg class="spark sp-{state}" viewBox="0 0 {width} {height}" '
            f'preserveAspectRatio="none">'
            f'<polygon class="spark-area" points="{area}"/>'
            f'<polyline class="spark-line" points="{poly}"/>'
            f'<circle class="spark-dot" cx="{last_x}" cy="{last_y}" r="2.4"/></svg>')


def kuma_bars(name, history, now_epoch, hours=24):
    """24 hourly colored blocks for one monitor. Each bucket = worst status seen
    that hour. Green=up, red=down, yellow=other, grey=no data."""
    buckets = [None] * hours
    start = now_epoch - hours * 3600
    for ep, st in history:
        if ep < start:
            continue
        idx = int((ep - start) // 3600)
        if idx < 0 or idx >= hours:
            continue
        cur = buckets[idx]
        # severity: down(0) worst, then other(2/3), then up(1)
        sev = {0: 3, 2: 2, 3: 2, 1: 1}.get(int(st), 1)
        prev = {None: 0, "up": 1, "other": 2, "down": 3}.get(cur, 0)
        if sev >= prev:
            buckets[idx] = {3: "down", 2: "other", 1: "up"}[sev]
    cells = ""
    for b in buckets:
        cls = {"up": "b-up", "down": "b-down", "other": "b-other"}.get(b, "b-none")
        cells += f'<span class="hbar {cls}"></span>'
    return f'<div class="hbar-row"><span class="hbar-name">{esc(name)[:20]}</span><span class="hbar-cells">{cells}</span></div>'


def unifi_device_rows(devices):
    rows = ""
    for dv in devices:
        scls = "dv-on" if dv.get("online") else "dv-off"
        rows += (f'<div class="dv {scls}"><span class="dv-dot"></span>'
                 f'<span class="dv-name">{esc(dv["name"])}</span>'
                 f'<span class="dv-kind">{esc(dv["kind"])}</span>'
                 f'<span class="dv-up">{esc(dv["uptime"])}</span></div>')
    return rows or '<div class="empty">No devices reported.</div>'


def render(data, gen_epoch, errors, trends=None):
    trends = trends or {"daily": {}, "kuma_history": {}}
    P = data.get("proxmox", {})
    D = data.get("docker", {})
    B = data.get("pbs", {})
    K = data.get("kuma", {})
    C = data.get("crowdsec", {})
    W = data.get("wazuh", {})
    U = data.get("unifi", {})
    A = data.get("adguard", {})
    UB = data.get("urbackup", {})
    Q = data.get("qnap", {})
    HA = data.get("homeassistant", {})
    A2 = data.get("adguard2", {})
    CF = data.get("cloudflare", {})
    NPM = data.get("npm", {})
    TS = data.get("tailscale", {})
    WG = data.get("wgdashboard", {})
    PX = data.get("plex", {})
    TA = data.get("tautulli", {})
    SO = data.get("sonarr", {})
    RA = data.get("radarr", {})
    SB = data.get("sabnzbd", {})
    OV = data.get("overseerr", {})
    PR = data.get("prowlarr", {})

    # overall health
    states = [v.get("state", "error") for v in data.values()]
    if "crit" in states or "error" in states:
        overall = "crit"
    elif "warn" in states:
        overall = "warn"
    elif "degraded" in states:
        overall = "degraded"
    else:
        overall = "ok"
    overall_txt = {"ok": "ALL SYSTEMS OPERATIONAL", "warn": "ATTENTION NEEDED",
                   "crit": "CRITICAL", "degraded": "DEGRADED"}[overall]

    # Render the generation time in Eastern (America/New_York). zoneinfo handles
    # the EDT/EST switch automatically - no hardcoded offset to drift twice a year.
    from datetime import datetime as _datetime, timezone as _timezone
    try:
        from zoneinfo import ZoneInfo
        _et = _datetime.fromtimestamp(gen_epoch, ZoneInfo("America/New_York"))
    except Exception:
        # Fallback: VM is UTC; apply a fixed -4h EDT offset if tzdata is missing.
        _et = _datetime.fromtimestamp(gen_epoch, _timezone.utc).astimezone()
    ts = _et.strftime("%a %b %-d, %Y %-I:%M %p ET")

    # ---- Row 1: status ----
    prox_body = (metric("VMs", f'{P.get("vms_running",0)}/{P.get("vms_total",0)}',
                        "crit" if P.get("down_vms") else "ok")
                 + metric("CPU", f'{P.get("cpu",0):.0f}%')
                 + metric("RAM", f'{P.get("mem_used",0):.0f}/{P.get("mem_total",0):.0f}G'))
    prox_sub = P.get("note") or (("DOWN: " + ", ".join(P["down_vms"])) if P.get("down_vms")
                                 else f'node {P.get("node","?")} up {P.get("uptime_d",0)}d')
    if P.get("state") == "error":
        prox_sub = P.get("error", "error")

    dock_body = (metric("Running", f'{D.get("running",0)}/{D.get("total",0)}',
                        "warn" if D.get("bad") else "ok")
                 + metric("Envs", D.get("envs", "-")))
    dock_sub = D.get("note") or D.get("error") or (
        ("; ".join(D.get("bad", [])[:3])) if D.get("bad") else "all containers healthy")

    pbs_fail = B.get("fail", 0)
    pbs_mstate = "crit" if pbs_fail else ("warn" if B.get("state") in ("warn", "crit") else "ok")
    pbs_body = (metric("Last Backup", B.get("last_backup", "?"), pbs_mstate)
                + metric("24h Tasks", f'{B.get("ok",0)} ok / {pbs_fail} fail',
                        "crit" if pbs_fail else ""))
    if B.get("datastores"):
        ds = B["datastores"][0]
        pbs_sub = f'datastore {esc(ds["name"])}: {ds["pct"]:.0f}% used'
    else:
        pbs_sub = B.get("error", "")
    if pbs_fail:
        pbs_sub = f'{pbs_fail} FAILED task(s) in 24h' + (f' · {pbs_sub}' if pbs_sub else '')

    kuma_body = (metric("Monitors", f'{K.get("up",0)}/{K.get("total",0)} up',
                       "crit" if K.get("down") else ("warn" if K.get("other") else "ok")))
    kuma_sub = K.get("note") or K.get("error") or (
        ("DOWN: " + ", ".join(K.get("down", []))) if K.get("down") else "all monitors up")

    # URBackup card
    ub_clients = UB.get("clients", [])
    ub_body = (metric("Clients", f'{UB.get("online",0)}/{UB.get("total",0)} online',
                     "warn" if UB.get("problems") else "ok"))
    if ub_clients:
        rows = []
        for c in ub_clients:
            mc = {"crit": "m-crit", "warn": "m-warn"}.get(c["state"], "")
            badge = "" if c["online"] else " (offline)"
            iss = f' · {c["issues"]} issue(s)' if c.get("issues") else ""
            rows.append(f'<div class="ubrow {mc}"><span class="ub-n">{esc(c["name"])}{badge}</span>'
                        f'<span class="ub-a">{esc(c["ago"])}{iss}</span></div>')
        ub_body += '<div class="ublist">' + "".join(rows) + "</div>"
    ub_sub = (UB.get("note") or UB.get("error")
              or (UB["problems"][0] if UB.get("problems") else "all clients backed up"))

    # Home Assistant card
    ha_body = (metric("Entities", HA.get("entities", 0))
               + metric("Alerts", HA.get("alerts_on", 0),
                       "crit" if HA.get("alerts_on") else "ok")
               + metric("Unavail", HA.get("unavailable", 0),
                       "warn" if HA.get("unavailable", 0) else ""))
    if HA.get("alert_names"):
        ha_sub = "ALERT: " + ", ".join(HA["alert_names"])
    elif HA.get("note") or HA.get("error"):
        ha_sub = HA.get("note") or HA.get("error")
    else:
        ha_sub = (f'{HA.get("domains",0)} domains · {HA.get("notifications",0)} notification(s)')

    row1 = (card("PROXMOX", P.get("state", "error"), prox_body, prox_sub)
            + card("DOCKER / PORTAINER", D.get("state", "error"), dock_body, dock_sub)
            + card("PBS BACKUPS", B.get("state", "error"), pbs_body, pbs_sub)
            + card("UPTIME KUMA", K.get("state", "error"), kuma_body, kuma_sub)
            + card("URBACKUP", UB.get("state", "error"), ub_body, ub_sub)
            + card("HOME ASSISTANT", HA.get("state", "error"), ha_body, ha_sub))

    # ---- Row 2: security ----
    daily = trends.get("daily", {})
    days_sorted = sorted(daily.keys())
    cs_series = [daily[d].get("crowdsec_bans") for d in days_sorted]
    cs_local_series = [daily[d].get("crowdsec_local") for d in days_sorted]
    ag_series = [daily[d].get("adguard_blocked") for d in days_sorted]
    ag2_series = [daily[d].get("adguard2_blocked") for d in days_sorted]

    cs_body = (metric("Active Bans", f'{C.get("bans",0):,}')
               + metric("Local Bans", f'{C.get("local_bans",0):,}')
               + metric("Detections 24h",
                        C.get("detections_24h") if C.get("detections_24h") is not None else "n/a"))
    cs_spark = sparkline(cs_series, state="crit")
    cs_body += f'<div class="trend"><span class="trend-lbl">bans {len(days_sorted)}d trend</span>{cs_spark}</div>'
    cs_sub = C.get("error") or (
        ("top: " + ", ".join(f"{k}({v})" for k, v in C.get("top", []))) if C.get("top")
        else "no behavioral bans")

    wz_body = metric("Agents", f'{W.get("active",0)}/{W.get("total",0)} online',
                     "warn" if W.get("down") else "ok")
    if "alerts_24h" in W:
        wz_body += metric("Alerts 24h", f'{W.get("alerts_24h",0):,}')
        wz_body += metric("High/Crit 24h", W.get("high_24h", 0),
                          "crit" if W.get("high_24h") else "ok")
    wz_sub = W.get("error") or (("offline: " + ", ".join(W.get("down", [])))
                                if W.get("down") else "all agents reporting")
    if W.get("alerts_err"):
        wz_sub += f" | indexer: {W['alerts_err']}"

    uni_body = (metric("WAN", esc(U.get("wan", "?")).upper(),
                      "crit" if U.get("wan") != "ok" else "ok")
                + metric("Clients", U.get("clients", 0))
                + metric("IPS 24h", U.get("ips_24h", 0),
                        "warn" if U.get("ips_24h", 0) else ""))
    # WiFi clients per SSID
    if U.get("ssids"):
        ssid_rows = "".join(
            f'<div class="ubrow"><span class="ub-n">{esc(s["name"])}</span>'
            f'<span class="ub-a">{s["clients"]} client{"s" if s["clients"]!=1 else ""}</span></div>'
            for s in U["ssids"])
        uni_body += '<div class="ublist">' + ssid_rows + "</div>"
    # Monthly WAN data usage + PIA VPN: full-width rows (NOT grid metrics) so
    # the values can't collide with each other in the wrapping flex grid.
    info_rows = ""
    if U.get("month_total") is not None:
        mo = f'{_hb_short(U.get("month_rx",0))}↓ / {_hb_short(U.get("month_tx",0))}↑'
        info_rows += (f'<div class="ubrow"><span class="ub-n">Mo. Data</span>'
                      f'<span class="ub-a">{esc(mo)}</span></div>')
    pia = U.get("pia")
    if pia:
        pcls = "" if pia.get("connected") else " m-crit"
        pia_txt = esc(pia.get("status", "?")) + ("" if pia.get("enabled") else " (disabled)")
        info_rows += (f'<div class="ubrow{pcls}"><span class="ub-n">'
                      f'VPN {esc(pia.get("name","PIA"))}</span>'
                      f'<span class="ub-a">{pia_txt}</span></div>')
    if info_rows:
        uni_body += '<div class="ublist">' + info_rows + "</div>"
    if U.get("devices"):
        uni_body += '<div class="dvlist">' + unifi_device_rows(U["devices"]) + "</div>"
    if U.get("latency") is not None:
        uni_sub = f'{esc(U.get("wan_ip","?"))} · {U.get("latency")}ms · ↓{U.get("down_mbps","?")}/↑{U.get("up_mbps","?")} Mbps'
    else:
        uni_sub = U.get("error") or esc(U.get("wan_ip", ""))

    ag_body = (metric("Queries", f'{A.get("queries",0):,}')
               + metric("Blocked", f'{A.get("block_pct",0):.1f}%',
                        "warn" if A.get("block_pct", 0) > 0 else ""))
    ag_spark = sparkline(ag_series, state="warn")
    ag_body += f'<div class="trend"><span class="trend-lbl">blocked {len(days_sorted)}d trend</span>{ag_spark}</div>'
    ag_sub = A.get("error") or f'{A.get("blocked",0):,} blocked · {A.get("avg_ms",0):.1f}ms avg'

    # AdGuard secondary instance (DNS2)
    ag2_body = (metric("Queries", f'{A2.get("queries",0):,}')
                + metric("Blocked", f'{A2.get("block_pct",0):.1f}%',
                         "warn" if A2.get("block_pct", 0) > 0 else ""))
    ag2_spark = sparkline(ag2_series, state="warn")
    ag2_body += f'<div class="trend"><span class="trend-lbl">blocked {len(days_sorted)}d trend</span>{ag2_spark}</div>'
    ag2_sub = (A2.get("note") or A2.get("error")
               or f'{A2.get("blocked",0):,} blocked · {A2.get("avg_ms",0):.1f}ms avg')

    # Cloudflare
    cf_body = (metric("Requests", f'{CF.get("requests",0):,}')
               + metric("Threats", f'{CF.get("threats",0):,}',
                        "warn" if CF.get("threats", 0) else "ok")
               + metric("Bandwidth", _hb(CF.get("bytes", 0))))
    if CF.get("waf_events") is not None:
        cf_body += (metric("WAF 24h", f'{CF.get("waf_events",0):,}')
                    + metric("Blocked 24h", f'{CF.get("waf_blocked",0):,}',
                             "warn" if CF.get("waf_blocked", 0) else ""))
    cf_sub = CF.get("note") or CF.get("error") or (
        f'WAF: {CF.get("waf_note")}' if CF.get("waf_note")
        else "requests/threats/bandwidth today · WAF events 24h")

    # Nginx Proxy Manager
    npm_body = (metric("Proxy Hosts", NPM.get("hosts", 0))
                + metric("Enabled", NPM.get("enabled", 0), "ok")
                + metric("Disabled", NPM.get("disabled", 0),
                         "warn" if NPM.get("disabled", 0) else "")
                + metric("Errored", NPM.get("errored", 0),
                         "crit" if NPM.get("errored", 0) else "")
                + metric("SSL Certs", NPM.get("certs", 0)))
    if NPM.get("problems"):
        npm_sub = NPM.get("note") or NPM.get("error") or ("; ".join(NPM["problems"][:4]))
    else:
        npm_sub = NPM.get("note") or NPM.get("error") or "all hosts enabled · no errors"

    # Tailscale
    ts_body = (metric("Devices", TS.get("total", 0))
               + metric("Online", TS.get("online", 0), "ok")
               + metric("Offline", TS.get("offline", 0),
                        "warn" if TS.get("offline", 0) else ""))
    if TS.get("exit_nodes"):
        ts_body += metric("Exit Node", esc(", ".join(TS["exit_nodes"])), "ok")
    if TS.get("devices"):
        ts_rows = "".join(
            f'<div class="ubrow {"" if dv["online"] else "m-warn"}">'
            f'<span class="ub-n">{esc(dv["name"])}{" · exit" if dv.get("exit_node") else ""}</span>'
            f'<span class="ub-a">{"online" if dv["online"] else "offline"}</span></div>'
            for dv in TS["devices"])
        ts_body += '<div class="ublist">' + ts_rows + "</div>"
    if TS.get("note") or TS.get("error"):
        ts_sub = TS.get("note") or TS.get("error")
    elif TS.get("soonest_expiry_days") is not None:
        ts_sub = f'{TS.get("online",0)}/{TS.get("total",0)} online · key expires in {TS["soonest_expiry_days"]}d'
    else:
        ts_sub = f'{TS.get("online",0)}/{TS.get("total",0)} online'

    # WGDashboard (WireGuard)
    wg_body = (metric("Peers Conn.", WG.get("connected", 0),
                      "ok" if WG.get("connected", 0) else "")
               + metric("Total Peers", WG.get("total_peers", 0))
               + metric("Interfaces",
                        f'{WG.get("ifaces_up",0)}/{WG.get("ifaces_total",0)} up',
                        "warn" if WG.get("ifaces_total", 0) and WG.get("ifaces_up", 0) < WG.get("ifaces_total", 0) else "ok"))
    if WG.get("interfaces"):
        wg_rows = "".join(
            f'<div class="ubrow {"" if i["up"] else "m-crit"}">'
            f'<span class="ub-n">{esc(i["name"])} ({esc(i["addr"])})</span>'
            f'<span class="ub-a">{"UP" if i["up"] else "DOWN"} · {i["connected"]}/{i["total"]}</span></div>'
            for i in WG["interfaces"])
        wg_body += '<div class="ublist">' + wg_rows + "</div>"
    wg_sub = (WG.get("note") or WG.get("error")
              or f'{WG.get("connected",0)} of {WG.get("total_peers",0)} peers connected')

    row2 = (card("CLOUDFLARE", CF.get("state", "error"), cf_body, cf_sub)
            + card("NGINX PROXY MGR", NPM.get("state", "error"), npm_body, npm_sub)
            + card("CROWDSEC", C.get("state", "error"), cs_body, cs_sub)
            + card("WAZUH SIEM", W.get("state", "error"), wz_body, wz_sub)
            + card("UNIFI UDM-SE", U.get("state", "error"), uni_body, uni_sub)
            + card("ADGUARD · DNS1", A.get("state", "error"), ag_body, ag_sub)
            + card("ADGUARD · DNS2", A2.get("state", "error"), ag2_body, ag2_sub)
            + card("TAILSCALE", TS.get("state", "error"), ts_body, ts_sub)
            + card("WGDASHBOARD", WG.get("state", "error"), wg_body, wg_sub))

    # ---- Media row: Plex, Tautulli, Sonarr, Radarr, SABnzbd, Overseerr, Prowlarr ----
    # Plex
    plex_body = (metric("Streams", PX.get("streams", 0),
                        "warn" if PX.get("streams", 0) else "ok")
                 + metric("Movies", f'{PX.get("movies",0):,}')
                 + metric("Shows", f'{PX.get("shows",0):,}'))
    plex_sub = (PX.get("note") or PX.get("error")
                or (f'{PX.get("streams",0)} active stream(s)' if PX.get("streams")
                    else "library idle"))

    # Tautulli
    tau_body = (metric("Plays Today", TA.get("plays_today", 0))
                + metric("Streaming", TA.get("streams", 0),
                        "warn" if TA.get("streams", 0) else "ok"))
    if TA.get("top_user"):
        tau_sub = f'top user: {esc(str(TA["top_user"]))} ({TA.get("top_plays",0)} plays)'
    else:
        tau_sub = TA.get("note") or TA.get("error") or "no plays today"

    # Sonarr
    son_body = (metric("Monitored", f'{SO.get("monitored",0):,}')
                + metric("Queue", SO.get("queue", 0),
                        "warn" if SO.get("queue", 0) else "")
                + metric("Missing", SO.get("missing", 0),
                        "warn" if SO.get("missing", 0) else ""))
    son_sub = (SO.get("note") or SO.get("error")
               or f'{SO.get("total",0):,} series total')

    # Radarr
    rad_body = (metric("Monitored", f'{RA.get("monitored",0):,}')
                + metric("Queue", RA.get("queue", 0),
                        "warn" if RA.get("queue", 0) else "")
                + metric("Missing", RA.get("missing", 0),
                        "warn" if RA.get("missing", 0) else ""))
    rad_sub = (RA.get("note") or RA.get("error")
               or f'{RA.get("total",0):,} movies total')

    # SABnzbd
    sab_body = (metric("Queue", SB.get("slots", 0),
                       "warn" if SB.get("slots", 0) else "ok")
                + metric("Speed", f'{SB.get("speed_mbps",0)} MB/s')
                + metric("Today", f'{SB.get("day_gb",0)} GB'))
    sab_sub = (SB.get("note") or SB.get("error")
               or f'status {esc(str(SB.get("status","Idle")))}'
               + (f' · {esc(str(SB.get("timeleft")))} left' if SB.get("slots") else ""))

    # Overseerr
    ov_body = (metric("Pending", OV.get("pending", 0),
                     "warn" if OV.get("pending", 0) else "ok")
               + metric("Approved", OV.get("approved", 0))
               + metric("Available", OV.get("available", 0)))
    ov_sub = (OV.get("note") or OV.get("error")
              or f'{OV.get("total",0)} total request(s)')

    # Prowlarr
    pr_body = (metric("Indexers", PR.get("total", 0))
               + metric("Healthy", PR.get("healthy", 0), "ok")
               + metric("Failing", PR.get("failing", 0),
                       "crit" if PR.get("failing", 0) else ""))
    pr_sub = (PR.get("note") or PR.get("error")
              or f'{PR.get("enabled",0)}/{PR.get("total",0)} enabled')

    media_row = (card("PLEX", PX.get("state", "error"), plex_body, plex_sub)
                 + card("TAUTULLI", TA.get("state", "error"), tau_body, tau_sub)
                 + card("SONARR", SO.get("state", "error"), son_body, son_sub)
                 + card("RADARR", RA.get("state", "error"), rad_body, rad_sub)
                 + card("SABNZBD", SB.get("state", "error"), sab_body, sab_sub)
                 + card("OVERSEERR", OV.get("state", "error"), ov_body, ov_sub)
                 + card("PROWLARR", PR.get("state", "error"), pr_body, pr_sub))

    # ---- Row 3: storage gauges ----
    gauges = "".join(donut(s["name"], s["pct"]) for s in P.get("storage", []))
    if not gauges:
        gauges = '<div class="empty">No storage volumes visible (Proxmox token ACL).</div>'
    row3 = f'<div class="gauges">{gauges}</div>'

    # ---- Row 4: certs + alerts ----
    cert_tiles = ""
    for c in K.get("certs", []):
        if c["days"] <= CERT_WARN_DAYS or not c["valid"]:
            ccls = "crit" if (c["days"] <= 14 or not c["valid"]) else "warn"
        else:
            ccls = "ok"
        label = "INVALID" if not c["valid"] else f'{c["days"]}d'
        cert_tiles += f'<div class="cert c-{ccls}"><div class="cert-d">{esc(label)}</div><div class="cert-n">{esc(c["name"])}</div></div>'
    if not cert_tiles:
        cert_tiles = '<div class="empty">No TLS certificate data.</div>'

    # active alerts aggregation
    alerts = []
    if P.get("down_vms"):
        alerts += [f"Proxmox VM down: {v}" for v in P["down_vms"]]
    for s in P.get("storage", []):
        if s["pct"] > 85:
            alerts.append(f'Storage {s["name"]} at {s["pct"]:.0f}%')
    if D.get("bad"):
        alerts += [f"Docker: {b}" for b in D["bad"][:5]]
    if B.get("fail"):
        alerts.append(f'PBS: {B["fail"]} failed backup task(s) in 24h')
    if B.get("state") == "warn" and not B.get("fail"):
        alerts.append(f'PBS: last backup {B.get("last_backup","?")}')
    for k in K.get("down", []):
        alerts.append(f"Monitor DOWN: {k}")
    for k, st in K.get("other", []):
        alerts.append(f"Monitor {st}: {k}")
    if W.get("down"):
        alerts += [f"Wazuh agent offline: {a}" for a in W["down"]]
    if U.get("wan") not in ("ok", "?"):
        alerts.append(f'UniFi WAN status: {U.get("wan")}')
    if U.get("ips_24h", 0):
        alerts.append(f'UniFi IPS: {U["ips_24h"]} detection(s) in 24h')
    for c in K.get("certs", []):
        if not c["valid"]:
            alerts.append(f'Cert INVALID: {c["name"]}')
        elif c["days"] <= 14:
            alerts.append(f'Cert expiring: {c["name"]} in {c["days"]}d')
    for key, v in data.items():
        if v.get("state") == "error":
            alerts.append(f'{key} collector error: {v.get("error","")}')
        elif v.get("state") == "degraded" and v.get("note"):
            alerts.append(f'{key}: {v.get("note")}')
    # URBackup problems
    for p in UB.get("problems", []):
        alerts.append(f"URBackup: {p}")
    # QNAP problems
    for u in Q.get("units", []):
        nm = u.get("host", u.get("label", "QNAP"))
        for p in u.get("problems", []):
            alerts.append(f"QNAP {nm}: {p}")
        if u.get("error"):
            alerts.append(f"QNAP {u.get('label','?')} ({u.get('ip','?')}): {u['error']}")
    # Home Assistant
    for an in HA.get("alert_names", []):
        alerts.append(f"Home Assistant alert active: {an}")
    # UniFi offline devices
    for dv in U.get("devices", []):
        if not dv.get("online"):
            alerts.append(f'UniFi device offline: {dv["name"]} ({dv["kind"]})')
    # Cloudflare / NPM
    if CF.get("waf_blocked"):
        alerts.append(f'Cloudflare WAF: {CF["waf_blocked"]:,} request(s) blocked in 24h')
    for p in NPM.get("problems", []):
        alerts.append(f"NPM: {p}")

    if alerts:
        alert_html = "".join(f'<li>{esc(a)}</li>' for a in alerts)
        alert_block = f'<ul class="alerts">{alert_html}</ul>'
    else:
        alert_block = '<div class="empty ok-empty">No active alerts. Nothing on fire.</div>'

    # ---- QNAP NAS section ----
    def qnap_card(u):
        st = u.get("state", "error")
        if u.get("error") or u.get("note"):
            body = f'<div class="empty">{esc(u.get("error") or u.get("note"))}</div>'
            title = f'{esc(u.get("label","QNAP"))} · {esc(u.get("ip","?"))}'
            return card(title, st, body)
        # temps
        ct, st_temp = u.get("cpu_temp"), u.get("sys_temp")
        sys_mc = "crit" if (st_temp is not None and st_temp >= 60) else (
            "warn" if (st_temp is not None and st_temp >= 50) else "")
        head = (metric("CPU °C", ct if ct is not None else "?")
                + metric("Sys °C", st_temp if st_temp is not None else "?", sys_mc)
                + metric("Fan", "OK" if u.get("fan_ok") else "FAULT",
                        "" if u.get("fan_ok") else "crit"))
        # volumes
        vol_html = ""
        for v in u.get("volumes", []):
            pcls = pct_color(v["pct"])
            vol_html += (f'<div class="qvol"><div class="qvol-top">'
                         f'<span>{esc(v["name"])}</span>'
                         f'<span class="qvol-pct q-{pcls}">{v["pct"]:.0f}%</span></div>'
                         f'<div class="qbar"><span class="qbar-f q-{pcls}" style="width:{min(v["pct"],100):.0f}%"></span></div>'
                         f'<div class="qvol-cap">{v["used_t"]:.1f} / {v["total_t"]:.1f} TB</div></div>')
        # disks
        disk_html = ""
        for dk in u.get("disks", []):
            hl = dk.get("health", "?")
            ok = hl.upper() in ("OK", "GOOD", "NORMAL")
            dcls = "q-ok" if ok else "q-crit"
            tmp = f'{dk["temp"]}°C' if dk.get("temp") is not None else "—"
            disk_html += (f'<div class="qdisk {dcls}"><span class="qd-dot"></span>'
                          f'<span class="qd-n">{esc(dk["alias"])}</span>'
                          f'<span class="qd-h">{esc(hl)}</span>'
                          f'<span class="qd-t">{esc(tmp)}</span></div>')
        sub = (f'{esc(u.get("model","?"))} · QTS · up {u.get("uptime_d","?")}d'
               + (f' · {len(u.get("disks",[]))} disks' if u.get("disks") else ""))
        body = (head
                + (f'<div class="qsec-l">Volumes</div>{vol_html}' if vol_html else "")
                + (f'<div class="qsec-l">Disk Health</div>{disk_html}' if disk_html else ""))
        title = f'{esc(u.get("host", u.get("label","QNAP")))} · {esc(u.get("ip","?"))}'
        return card(title, st, body, sub)

    qnap_units = Q.get("units", [])
    if qnap_units:
        qnap_cards = "".join(qnap_card(u) for u in qnap_units)
    else:
        qnap_cards = '<div class="empty">No QNAP units configured.</div>'

    # ---- Uptime Kuma 24h history bars ----
    kuma_hist = trends.get("kuma_history", {})
    smap = K.get("status_map", {})
    hist_rows = ""
    if kuma_hist:
        # order: down first, then by name
        def sort_key(name):
            cur = smap.get(name, 1)
            return (0 if cur == 0 else (1 if cur not in (1,) else 2), name.lower())
        for name in sorted(kuma_hist.keys(), key=sort_key):
            hist_rows += kuma_bars(name, kuma_hist[name], gen_epoch, hours=KUMA_HIST_HOURS)
        hist_block = (f'<div class="hbar-head"><span class="hbar-name"></span>'
                      f'<span class="hbar-legend">-24h &rarr; now &nbsp; '
                      f'<span class="hbar b-up"></span>up '
                      f'<span class="hbar b-down"></span>down '
                      f'<span class="hbar b-other"></span>other '
                      f'<span class="hbar b-none"></span>no data</span></div>'
                      + hist_rows)
    else:
        hist_block = '<div class="empty">Collecting uptime history&hellip; bars populate after a few regen cycles.</div>'

    return PAGE.format(
        ts=esc(ts), overall=overall, overall_txt=overall_txt,
        row1=row1, row2=row2, media_row=media_row, row3=row3,
        qnap_cards=qnap_cards, kuma_history=hist_block,
        cert_tiles=cert_tiles, alert_block=alert_block)


PAGE = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>Homelab Homelab NOC</title>
<style>
  :root {{
    --bg:#0a0e0a; --panel:#0f150f; --panel2:#121a12; --line:#1c2a1c;
    --green:#00ff41; --green-dim:#0c9b30; --txt:#c8e6c8; --muted:#6f8a6f;
    --warn:#ffcc00; --crit:#ff3b3b; --degr:#7a7a7a;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--txt);
    font-family:"SF Mono",Menlo,Consolas,"Roboto Mono",monospace; font-size:14px;
    background-image:radial-gradient(circle at 50% 0%, #0d160d 0%, #060906 70%); }}
  .topbar {{ display:flex; align-items:center; justify-content:space-between;
    padding:14px 22px; border-bottom:1px solid var(--line);
    background:linear-gradient(180deg,#0c130c,#080b08); position:sticky; top:0; z-index:5; }}
  .brand {{ display:flex; align-items:baseline; gap:14px; }}
  .brand h1 {{ font-size:20px; margin:0; color:var(--green); letter-spacing:2px;
    text-shadow:0 0 8px rgba(0,255,65,.4); }}
  .brand .tag {{ color:var(--muted); font-size:11px; letter-spacing:3px; }}
  .top-right {{ display:flex; align-items:center; gap:18px; }}
  .ts {{ color:var(--muted); font-size:12px; }}
  .ts b {{ color:var(--txt); }}
  .health {{ display:flex; align-items:center; gap:9px; padding:7px 15px;
    border:1px solid var(--line); border-radius:4px; font-weight:bold; letter-spacing:1px;
    font-size:12px; }}
  .health .led {{ width:12px; height:12px; border-radius:50%; }}
  .h-ok    {{ color:var(--green); border-color:var(--green-dim); }}
  .h-ok .led {{ background:var(--green); box-shadow:0 0 10px var(--green); animation:pulse 2s infinite; }}
  .h-warn  {{ color:var(--warn); border-color:#8a7400; }}
  .h-warn .led {{ background:var(--warn); box-shadow:0 0 10px var(--warn); }}
  .h-crit  {{ color:var(--crit); border-color:#8a1d1d; }}
  .h-crit .led {{ background:var(--crit); box-shadow:0 0 12px var(--crit); animation:pulse 1s infinite; }}
  .h-degraded {{ color:var(--degr); border-color:#3a3a3a; }}
  .h-degraded .led {{ background:var(--degr); }}
  @keyframes pulse {{ 0%,100%{{opacity:1}} 50%{{opacity:.35}} }}
  .wrap {{ padding:18px 22px 40px; max-width:1500px; margin:0 auto; }}
  .section-label {{ color:var(--green-dim); font-size:11px; letter-spacing:3px;
    margin:22px 4px 10px; text-transform:uppercase; border-bottom:1px solid var(--line);
    padding-bottom:6px; }}
  .row {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; }}
  @media(max-width:1100px){{ .row{{grid-template-columns:repeat(2,1fr);}} }}
  @media(max-width:620px){{ .row{{grid-template-columns:1fr;}} }}
  .card {{ background:linear-gradient(180deg,var(--panel),var(--panel2));
    border:1px solid var(--line); border-left:3px solid var(--degr); border-radius:6px;
    padding:14px 16px; box-shadow:0 2px 10px rgba(0,0,0,.4); }}
  .card.s-ok {{ border-left-color:var(--green); }}
  .card.s-warn {{ border-left-color:var(--warn); }}
  .card.s-crit {{ border-left-color:var(--crit); }}
  .card.s-degraded, .card.s-error {{ border-left-color:var(--degr); }}
  .card-h {{ display:flex; align-items:center; gap:9px; margin-bottom:12px; }}
  .card-h h3 {{ margin:0; font-size:12px; letter-spacing:2px; color:var(--txt); font-weight:600; }}
  .card-h .dot {{ width:8px; height:8px; border-radius:50%; background:var(--degr); }}
  .s-ok .dot {{ background:var(--green); box-shadow:0 0 7px var(--green); }}
  .s-warn .dot {{ background:var(--warn); box-shadow:0 0 7px var(--warn); }}
  .s-crit .dot {{ background:var(--crit); box-shadow:0 0 7px var(--crit); }}
  .card-b {{ display:flex; gap:10px; flex-wrap:wrap; }}
  .metric {{ flex:1; min-width:70px; }}
  .metric .m-v {{ font-size:20px; color:var(--green); font-weight:bold;
    text-shadow:0 0 6px rgba(0,255,65,.25); white-space:nowrap; }}
  .metric .m-l {{ font-size:10px; color:var(--muted); letter-spacing:1px;
    text-transform:uppercase; margin-top:3px; }}
  .metric.m-warn .m-v {{ color:var(--warn); text-shadow:0 0 6px rgba(255,204,0,.25); }}
  .metric.m-crit .m-v {{ color:var(--crit); text-shadow:0 0 6px rgba(255,59,59,.3); }}
  .sub {{ margin-top:11px; padding-top:9px; border-top:1px solid var(--line);
    font-size:11px; color:var(--muted); line-height:1.5; word-break:break-word; }}
  .gauges {{ display:flex; flex-wrap:wrap; gap:10px; justify-content:flex-start; }}
  .gauge {{ width:140px; }}
  .gauge svg {{ width:140px; height:140px; }}
  .g-track {{ fill:none; stroke:#15201510; stroke:#162016; stroke-width:11; }}
  .g-val {{ fill:none; stroke-width:11; stroke-linecap:round; transition:stroke-dasharray .5s; }}
  .g-ok .g-val {{ stroke:var(--green); filter:drop-shadow(0 0 4px rgba(0,255,65,.5)); }}
  .g-warn .g-val {{ stroke:var(--warn); filter:drop-shadow(0 0 4px rgba(255,204,0,.5)); }}
  .g-crit .g-val {{ stroke:var(--crit); filter:drop-shadow(0 0 4px rgba(255,59,59,.5)); }}
  .g-pct {{ fill:var(--txt); font-size:22px; text-anchor:middle; font-weight:bold; }}
  .g-ok .g-pct {{ fill:var(--green); }}
  .g-warn .g-pct {{ fill:var(--warn); }}
  .g-crit .g-pct {{ fill:var(--crit); }}
  .g-lbl {{ fill:var(--muted); font-size:10px; text-anchor:middle; letter-spacing:.5px; }}
  .certs {{ display:flex; flex-wrap:wrap; gap:12px; }}
  .cert {{ background:var(--panel); border:1px solid var(--line); border-radius:6px;
    padding:14px 18px; min-width:130px; text-align:center; border-top:3px solid var(--green); }}
  .cert.c-ok {{ border-top-color:var(--green); }}
  .cert.c-warn {{ border-top-color:var(--warn); }}
  .cert.c-crit {{ border-top-color:var(--crit); }}
  .cert-d {{ font-size:26px; font-weight:bold; color:var(--green); }}
  .c-warn .cert-d {{ color:var(--warn); }}
  .c-crit .cert-d {{ color:var(--crit); }}
  .cert-n {{ font-size:11px; color:var(--muted); margin-top:5px; word-break:break-word; }}
  .alerts {{ list-style:none; margin:0; padding:0; }}
  .alerts li {{ background:var(--panel); border-left:3px solid var(--crit);
    padding:9px 14px; margin-bottom:7px; border-radius:4px; font-size:13px; color:#ffd9d9; }}
  .empty {{ color:var(--muted); font-size:12px; padding:14px; font-style:italic; }}
  .ok-empty {{ color:var(--green-dim); }}
  .twocol {{ display:grid; grid-template-columns:1fr 1fr; gap:14px; }}
  @media(max-width:900px){{ .twocol{{grid-template-columns:1fr;}} }}
  .panelbox {{ background:linear-gradient(180deg,var(--panel),var(--panel2));
    border:1px solid var(--line); border-radius:6px; padding:16px; }}
  .panelbox h4 {{ margin:0 0 12px; font-size:11px; letter-spacing:2px; color:var(--green-dim); }}
  /* sparkline trend */
  .trend {{ width:100%; margin-top:10px; padding-top:9px; border-top:1px dashed var(--line); }}
  .trend-lbl {{ font-size:9px; color:var(--muted); letter-spacing:1px; text-transform:uppercase; display:block; margin-bottom:3px; }}
  .spark {{ width:100%; height:34px; display:block; }}
  .spark-line {{ fill:none; stroke:var(--green); stroke-width:1.6; }}
  .spark-area {{ fill:rgba(0,255,65,.08); stroke:none; }}
  .spark-dot {{ fill:var(--green); }}
  .sp-warn .spark-line {{ stroke:var(--warn); }} .sp-warn .spark-area {{ fill:rgba(255,204,0,.08); }} .sp-warn .spark-dot {{ fill:var(--warn); }}
  .sp-crit .spark-line {{ stroke:var(--crit); }} .sp-crit .spark-area {{ fill:rgba(255,59,59,.08); }} .sp-crit .spark-dot {{ fill:var(--crit); }}
  .spark-empty {{ font-size:10px; color:var(--muted); font-style:italic; padding:8px 0; }}
  /* UniFi device list */
  .dvlist {{ width:100%; margin-top:10px; padding-top:9px; border-top:1px dashed var(--line); }}
  .dv {{ display:flex; align-items:center; gap:8px; padding:3px 0; font-size:11px; }}
  .dv-dot {{ width:7px; height:7px; border-radius:50%; background:var(--green); box-shadow:0 0 5px var(--green); flex:none; }}
  .dv-off .dv-dot {{ background:var(--crit); box-shadow:0 0 5px var(--crit); }}
  .dv-name {{ color:var(--txt); flex:1; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .dv-kind {{ color:var(--muted); font-size:9px; text-transform:uppercase; letter-spacing:1px; width:88px; text-align:right; }}
  .dv-up {{ color:var(--green-dim); font-size:10px; width:64px; text-align:right; }}
  .dv-off .dv-up {{ color:var(--crit); }}
  /* URBackup client list */
  .ublist {{ width:100%; margin-top:10px; padding-top:9px; border-top:1px dashed var(--line); }}
  .ubrow {{ display:flex; justify-content:space-between; gap:10px; padding:3px 0; font-size:11px; align-items:baseline; }}
  .ubrow .ub-n {{ color:var(--txt); white-space:nowrap; flex:0 0 auto; }}
  .ubrow .ub-a {{ color:var(--green-dim); white-space:nowrap; text-align:right; flex:1 1 auto;
    overflow:hidden; text-overflow:ellipsis; }}
  .ubrow.m-warn .ub-a {{ color:var(--warn); }} .ubrow.m-crit .ub-a {{ color:var(--crit); }}
  .ubrow.m-warn .ub-n, .ubrow.m-crit .ub-n {{ color:#ffd9d9; }}
  /* QNAP cards */
  .qsec-l {{ width:100%; font-size:9px; letter-spacing:2px; color:var(--green-dim);
    text-transform:uppercase; margin:12px 0 6px; border-bottom:1px solid var(--line); padding-bottom:3px; }}
  .qvol {{ width:100%; margin-bottom:9px; }}
  .qvol-top {{ display:flex; justify-content:space-between; font-size:11px; color:var(--txt); margin-bottom:3px; }}
  .qvol-pct {{ font-weight:bold; }}
  .qbar {{ height:7px; background:#0c140c; border:1px solid var(--line); border-radius:4px; overflow:hidden; }}
  .qbar-f {{ display:block; height:100%; background:var(--green); }}
  .qvol-cap {{ font-size:9px; color:var(--muted); margin-top:2px; }}
  .q-ok {{ color:var(--green); }} .q-warn {{ color:var(--warn); }} .q-crit {{ color:var(--crit); }}
  .qbar-f.q-ok {{ background:var(--green); }} .qbar-f.q-warn {{ background:var(--warn); }} .qbar-f.q-crit {{ background:var(--crit); }}
  .qdisk {{ display:flex; align-items:center; gap:8px; font-size:11px; padding:2px 0; width:100%; }}
  .qd-dot {{ width:7px; height:7px; border-radius:50%; background:var(--green); box-shadow:0 0 5px var(--green); flex:none; }}
  .qdisk.q-crit .qd-dot {{ background:var(--crit); box-shadow:0 0 5px var(--crit); }}
  .qd-n {{ flex:1; color:var(--txt); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .qd-h {{ width:60px; text-align:right; }} .qdisk.q-ok .qd-h {{ color:var(--green); }} .qdisk.q-crit .qd-h {{ color:var(--crit); }}
  .qd-t {{ width:48px; text-align:right; color:var(--muted); font-size:10px; }}
  /* Uptime Kuma 24h history bars */
  .hbar-row, .hbar-head {{ display:flex; align-items:center; gap:10px; margin-bottom:5px; }}
  .hbar-name {{ width:170px; font-size:11px; color:var(--txt); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; flex:none; }}
  .hbar-cells {{ display:flex; gap:2px; flex:1; }}
  .hbar {{ display:inline-block; width:13px; height:18px; border-radius:2px; flex:1; min-width:6px; }}
  .hbar-head .hbar {{ width:13px; height:13px; flex:none; min-width:13px; vertical-align:middle; margin:0 2px 0 8px; }}
  .hbar-legend {{ font-size:10px; color:var(--muted); letter-spacing:1px; }}
  .b-up {{ background:var(--green-dim); }}
  .b-down {{ background:var(--crit); }}
  .b-other {{ background:var(--warn); }}
  .b-none {{ background:#1a241a; }}
  footer {{ text-align:center; color:#2c402c; font-size:10px; padding:20px;
    letter-spacing:2px; }}
</style></head>
<body>
  <div class="topbar">
    <div class="brand">
      <h1>Homelab Homelab</h1><span class="tag">NOC // ANTON</span>
    </div>
    <div class="top-right">
      <div class="ts">UPDATED <b>{ts}</b></div>
      <div class="health h-{overall}"><span class="led"></span>{overall_txt}</div>
    </div>
  </div>
  <div class="wrap">
    <div class="section-label">System Status</div>
    <div class="row">{row1}</div>
    <div class="section-label">Security &amp; Network</div>
    <div class="row">{row2}</div>
    <div class="section-label">Media &amp; Downloads</div>
    <div class="row">{media_row}</div>
    <div class="section-label">QNAP Storage Appliances</div>
    <div class="row">{qnap_cards}</div>
    <div class="section-label">Proxmox Storage Utilization</div>
    <div class="panelbox">{row3}</div>
    <div class="section-label">Uptime History (last 24h)</div>
    <div class="panelbox">{kuma_history}</div>
    <div class="section-label">Certificates &amp; Active Alerts</div>
    <div class="twocol">
      <div class="panelbox"><h4>TLS CERT EXPIRY</h4><div class="certs">{cert_tiles}</div></div>
      <div class="panelbox"><h4>ACTIVE ALERTS</h4>{alert_block}</div>
    </div>
  </div>
  <footer>MRDTECH INFRASTRUCTURE MONITORING · AUTO-REFRESH 60s · REGEN 15m</footer>
</body></html>"""


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    gen_epoch = time.time()
    data = gather()
    errors = {k: v.get("error") for k, v in data.items() if v.get("state") == "error"}
    try:
        trends = update_trends(data, gen_epoch)
    except Exception as e:
        trends = load_trends()
        print(f"warn: trend update failed: {type(e).__name__}: {str(e)[:80]}")
    page = render(data, gen_epoch, errors, trends)
    tmp = OUT_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(page)
    os.replace(tmp, OUT_FILE)  # atomic - server never serves a half-written file
    ok = sum(1 for v in data.values() if v.get("state") == "ok")
    print(f"dashboard written: {OUT_FILE} ({len(page):,} bytes) | "
          f"{ok}/{len(data)} sources green | errors: {list(errors) or 'none'}")


if __name__ == "__main__":
    main()
