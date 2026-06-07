#!/usr/bin/env python3
"""
Weekly infrastructure report - Saturdays 8am ET via Hermes cron (no_agent).
stdout delivered verbatim to Telegram. Stdlib only.

Sections:
  - Backup success rate: PBS task success % over last 7d + URBackup client status
  - Uptime stats: Uptime Kuma current up/down + 7d availability from history
  - Top AdGuard blocked domains (all-time top list from /control/stats)
  - CrowdSec trend: ban count change over the retained daily snapshots
    (~/.hermes/state/dashboard_trends.json, written by generate_dashboard.py)

Per-source isolation: one failure never kills the report.
"""
import base64, hashlib, json, os, re, ssl, time
import urllib.request, urllib.parse, http.cookiejar

ENV_PATH = os.path.expanduser("~/.hermes/.env")
TRENDS = os.path.expanduser("~/.hermes/state/dashboard_trends.json")
TIMEOUT = 14
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


E = load_env(ENV_PATH)


def req(url, headers=None, data=None, method=None, cookiejar=None):
    h = dict(headers or {})
    if isinstance(data, dict):
        data = json.dumps(data).encode(); h.setdefault("Content-Type", "application/json")
    elif isinstance(data, str):
        data = data.encode()
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    if cookiejar is not None:
        op = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=CTX),
            urllib.request.HTTPCookieProcessor(cookiejar))
        return op.open(r, timeout=TIMEOUT).read().decode("utf-8", "replace")
    return urllib.request.urlopen(r, timeout=TIMEOUT, context=CTX).read().decode("utf-8", "replace")


def jget(url, headers=None, data=None, method=None, cookiejar=None):
    return json.loads(req(url, headers, data, method, cookiejar))


def _b64(s):
    return base64.b64encode(s.encode()).decode()


# ---------------- Backup success rate ----------------
def backups():
    out = []
    # PBS: 7d task success rate
    try:
        tk = jget("https://10.0.0.77:8007/api2/json/access/ticket",
                  data=urllib.parse.urlencode({
                      "username": E.get("PBS_USERNAME", "root@pam"),
                      "password": E.get("PBS_PASSWORD", "")}),
                  headers={"Content-Type": "application/x-www-form-urlencoded"},
                  method="POST")["data"]["ticket"]
        cookie = {"Cookie": f"PBSAuthCookie={urllib.parse.quote(tk, safe='')}"}
        since = int(time.time()) - 7 * 86400
        tasks = jget(f"https://10.0.0.77:8007/api2/json/nodes/localhost/tasks"
                     f"?since={since}&limit=2000", cookie)["data"]
        bk = [t for t in tasks if t.get("worker_type") == "backup" and "endtime" in t]
        ok = [t for t in bk if t.get("status") == "OK"]
        fail = [t for t in bk if t.get("status") not in ("OK", None)]
        rate = (100 * len(ok) / len(bk)) if bk else 0
        flag = "  <-- CHECK" if fail else ""
        out.append(f"  PBS: {len(ok)}/{len(bk)} backup tasks OK ({rate:.1f}%){flag}")
        # other task types
        verify = [t for t in tasks if t.get("worker_type") == "verify" and "endtime" in t]
        vok = sum(1 for t in verify if t.get("status") == "OK")
        if verify:
            out.append(f"  PBS verify: {vok}/{len(verify)} OK")
        for t in fail[:5]:
            out.append(f"    FAIL: {t.get('worker_type')} {str(t.get('status'))[:70]}")
    except Exception as e:
        out.append(f"  PBS: UNAVAILABLE ({type(e).__name__}: {str(e)[:80]})")
    # URBackup: client backup freshness
    try:
        out.append(urbackup_summary())
    except Exception as e:
        out.append(f"  URBackup: UNAVAILABLE ({type(e).__name__}: {str(e)[:80]})")
    return "\n".join(out)


def urbackup_summary():
    base = E.get("URBACKUP_URL", "http://10.0.0.76:55414").rstrip("/")
    user = E.get("URBACKUP_USERNAME", "admin")
    pw = E.get("URBACKUP_PASSWORD", "")
    if not pw or pw.startswith("<"):
        return "  URBackup: URBACKUP_PASSWORD not set"

    def api(action, body=""):
        r = urllib.request.Request(base + "/x?a=" + action, data=body.encode(),
                                   method="POST",
                                   headers={"Content-Type": "application/json; charset=utf-8"})
        return json.loads(urllib.request.urlopen(r, timeout=TIMEOUT, context=CTX).read().decode("utf-8", "replace"))

    s = api("salt", "username=" + urllib.parse.quote(user))
    salt, rnd = s.get("salt", ""), s.get("rnd", "")
    rounds = int(s.get("pbkdf2_rounds", 0) or 0)
    ses = s.get("ses")
    pwmd5 = hashlib.md5((salt + pw).encode()).hexdigest()
    if rounds > 0:
        pwmd5 = hashlib.pbkdf2_hmac("sha256", bytes.fromhex(pwmd5), salt.encode(), rounds, dklen=32).hex()
    final = hashlib.md5((rnd + pwmd5).encode()).hexdigest()
    body = "username=" + urllib.parse.quote(user) + "&password=" + final + (f"&ses={ses}" if ses else "")
    if not api("login", body).get("success"):
        return "  URBackup: login failed"
    clients = api("status", "ses=" + ses if ses else "").get("status", [])
    fresh = sum(1 for c in clients if c.get("lastbackup", 0)
                and (time.time() - c["lastbackup"]) < 26 * 3600)
    issues = sum(1 for c in clients if c.get("last_filebackup_issues", 0))
    flag = "  <-- CHECK" if fresh < len(clients) else ""
    line = f"  URBackup: {fresh}/{len(clients)} clients backed up <26h{flag}"
    if issues:
        line += f"; {issues} with issues"
    return line


# ---------------- Uptime stats ----------------
def uptime():
    base = E.get("UPTIME_KUMA_URL", "").strip().rstrip("/")
    key = E.get("UPTIME_KUMA_API_KEY", "").strip()
    if not base or not key or key.startswith("<"):
        return "  UNAVAILABLE - Uptime Kuma not configured"
    auth = {"Authorization": "Basic " + _b64(f":{key}")}
    text = req(f"{base}/metrics", auth)
    status = {}
    for line in text.splitlines():
        if line.startswith("monitor_status{"):
            m = re.search(r'monitor_name="([^"]*)"', line)
            if not m:
                continue
            try:
                status[m.group(1)] = float(line.rsplit("}", 1)[1])
            except (ValueError, IndexError):
                pass
    up = sum(1 for v in status.values() if v == 1)
    down = sorted(k for k, v in status.items() if v == 0)
    out = [f"  monitors: {up}/{len(status)} currently up"]
    if down:
        out.append("  DOWN now: " + ", ".join(down))
    # 7d-ish availability from kuma_history samples
    try:
        with open(TRENDS, encoding="utf-8") as f:
            hist = json.load(f).get("kuma_history", {})
        avails = []
        for name, samples in hist.items():
            if not samples:
                continue
            ups = sum(1 for _, s in samples if s == 1)
            avails.append((name, 100 * ups / len(samples), len(samples)))
        worst = sorted((a for a in avails if a[1] < 100), key=lambda x: x[1])[:5]
        if worst:
            out.append("  lowest availability (from tracked history):")
            for name, pct, n in worst:
                out.append(f"    {name}: {pct:.1f}% ({n} samples)")
        elif avails:
            out.append(f"  tracked availability: 100% across {len(avails)} monitors")
    except Exception:
        pass
    return "\n".join(out)


# ---------------- Top AdGuard blocked domains ----------------
def adguard_top():
    s = jget("http://10.0.0.21/control/stats",
             {"Authorization": "Basic " + _b64(f"mdziegiel:{E.get('ADGUARD_PASSWORD','')}")})
    tot = s.get("num_dns_queries", 0)
    blk = s.get("num_blocked_filtering", 0)
    pct = (100 * blk / tot) if tot else 0
    out = [f"  {blk:,} blocked of {tot:,} queries ({pct:.1f}%)", "  top blocked domains:"]
    for d in s.get("top_blocked_domains", [])[:10]:
        for dom, cnt in d.items():
            out.append(f"    {cnt:>10,}  {dom}")
    return "\n".join(out)


# ---------------- CrowdSec trend ----------------
def crowdsec_trend():
    # current
    out = []
    try:
        dec = jget("http://10.0.0.237:18080/v1/decisions",
                   {"X-Api-Key": E.get("CROWDSEC_API_KEY", "")})
        cur = len(dec) if isinstance(dec, list) else 0
        local = sum(1 for x in dec if x.get("origin") not in ("lists", "CAPI")) if isinstance(dec, list) else 0
        out.append(f"  current active bans: {cur:,} ({local} behavioral)")
    except Exception as e:
        out.append(f"  current bans: UNAVAILABLE ({type(e).__name__})")
    # trend from daily snapshots
    try:
        with open(TRENDS, encoding="utf-8") as f:
            daily = json.load(f).get("daily", {})
        days = sorted(daily.keys())
        series = [(d, daily[d].get("crowdsec_bans")) for d in days if daily[d].get("crowdsec_bans") is not None]
        if len(series) >= 2:
            first_d, first_v = series[0]
            last_d, last_v = series[-1]
            delta = last_v - first_v
            sign = "+" if delta >= 0 else ""
            out.append(f"  trend {first_d}->{last_d}: {first_v:,} -> {last_v:,} ({sign}{delta:,})")
        elif series:
            out.append(f"  trend: only {len(series)} snapshot(s) so far ({series[-1][1]:,} bans)")
        else:
            out.append("  trend: no snapshots yet (dashboard builds history daily)")
    except Exception:
        out.append("  trend: no history file yet")
    return "\n".join(out)


# ---------------- Cloudflare (weekly) ----------------
def cloudflare_week():
    import datetime as _dt
    token = E.get("CLOUDFLARE_TOKEN", "").strip()
    zone = E.get("CLOUDFLARE_ZONE_ID", "").strip()
    if not token or not zone or token.startswith("<"):
        return "  UNAVAILABLE - Cloudflare token/zone not set"
    api = "https://api.cloudflare.com/client/v4/graphql"
    auth = {"Authorization": f"Bearer {token}"}
    since = (_dt.date.today() - _dt.timedelta(days=7)).isoformat()
    q = ("query($z:String!,$d:String!){viewer{zones(filter:{zoneTag:$z}){"
         "httpRequests1dGroups(limit:7,filter:{date_geq:$d}){"
         "dimensions{date} sum{requests bytes threats}}}}}")
    r = jget(api, auth, {"query": q, "variables": {"z": zone, "d": since}}, "POST")
    if r.get("errors"):
        return "  UNAVAILABLE - CF: " + str(r["errors"][0].get("message", ""))[:80]
    groups = r["data"]["viewer"]["zones"][0]["httpRequests1dGroups"]
    treq = sum(g["sum"]["requests"] for g in groups)
    tthr = sum(g["sum"]["threats"] for g in groups)
    tby = sum(g["sum"]["bytes"] for g in groups)
    gb = tby / (1024 ** 3)
    out = [f"  7d totals: {treq:,} requests · {tthr:,} threats · {gb:,.1f} GB",
           "  daily requests:"]
    for g in sorted(groups, key=lambda x: x["dimensions"]["date"]):
        s = g["sum"]
        out.append(f"    {g['dimensions']['date']}: {s['requests']:>10,} req · {s['threats']:>5,} threats")
    # WAF blocked (best-effort; needs firewall scope)
    dt7 = (_dt.datetime.now(_dt.UTC) - _dt.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    qf = ("query($z:String!,$d:Time!){viewer{zones(filter:{zoneTag:$z}){"
          "blk:firewallEventsAdaptiveGroups(limit:1,filter:{datetime_geq:$d,action:\"block\"}){count}}}}")
    try:
        rf = jget(api, auth, {"query": qf, "variables": {"z": zone, "d": dt7}}, "POST")
        if rf.get("errors"):
            msg = str(rf["errors"][0].get("message", ""))
            out.append("  WAF blocked 7d: n/a (" +
                       ("token lacks Firewall Analytics scope" if "access" in msg else msg[:50]) + ")")
        else:
            blk = (rf["data"]["viewer"]["zones"][0].get("blk") or [{}])[0].get("count", 0)
            out.append(f"  WAF blocked 7d: {blk:,}")
    except Exception:
        out.append("  WAF blocked 7d: n/a")
    return "\n".join(out)


# ---------------- Nginx Proxy Manager (weekly) ----------------
def npm_week():
    base = E.get("NPM_URL", "").strip().rstrip("/")
    email = E.get("NPM_EMAIL", "").strip()
    pw = E.get("NPM_PASSWORD", "").strip()
    if not base or not email or not pw or pw.startswith("<"):
        return "  UNAVAILABLE - NPM creds not set"
    tok = jget(f"{base}/api/tokens",
               data={"identity": email, "secret": pw}, method="POST").get("token")
    if not tok:
        return "  UNAVAILABLE - NPM auth returned no token"
    auth = {"Authorization": f"Bearer {tok}"}
    hosts = jget(f"{base}/api/nginx/proxy-hosts", auth)
    enabled = sum(1 for h in hosts if h.get("enabled"))
    disabled = [(h.get("domain_names") or ["?"])[0] for h in hosts if not h.get("enabled")]
    errored = [(h.get("domain_names") or ["?"])[0] for h in hosts
               if (h.get("meta") or {}).get("nginx_online") is False
               or (h.get("meta") or {}).get("nginx_err")]
    certs = jget(f"{base}/api/nginx/certificates", auth)
    now = time.time()
    expiring = []
    for c in certs:
        exp = c.get("expires_on")
        if not exp:
            continue
        try:
            ep = time.mktime(time.strptime(exp[:19], "%Y-%m-%dT%H:%M:%S"))
            days = (ep - now) / 86400
            if days <= 30:
                expiring.append((c.get("nice_name") or (c.get("domain_names") or ["?"])[0], int(days)))
        except Exception:
            pass
    flag = "  <-- CHECK" if (disabled or errored) else ""
    out = [f"  proxy hosts: {len(hosts)} ({enabled} enabled, {len(disabled)} disabled){flag}",
           f"  SSL certificates: {len(certs)}"]
    if disabled:
        out.append("  DISABLED: " + ", ".join(disabled))
    if errored:
        out.append("  ERRORED: " + ", ".join(errored))
    if expiring:
        out.append("  certs expiring <=30d:")
        for nm, d in sorted(expiring, key=lambda x: x[1]):
            out.append(f"    {nm}: {d}d")
    return "\n".join(out)


SECTIONS = [
    ("BACKUP SUCCESS RATE (7d)", backups),
    ("UPTIME STATS", uptime),
    ("CLOUDFLARE (7d)", cloudflare_week),
    ("NGINX PROXY MANAGER", npm_week),
    ("TOP ADGUARD BLOCKED DOMAINS", adguard_top),
    ("CROWDSEC TREND", crowdsec_trend),
]


def main():
    now = time.strftime("%a %Y-%m-%d %H:%M %Z")
    out = [f"Homelab Weekly Infrastructure Report  -  {now}", "=" * 48]
    problems = 0
    for title, fn in SECTIONS:
        out.append(f"\n[{title}]")
        try:
            body = fn()
            out.append(body)
            if any(k in body for k in ("FAIL", "DOWN", "UNAVAILABLE", "CHECK")):
                problems += 1
        except Exception as e:
            out.append(f"  ERROR: {type(e).__name__}: {str(e)[:120]}")
            problems += 1
    out.insert(1, "ALL GREEN" if problems == 0 else f"{problems} section(s) need attention")
    print("\n".join(out))


if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, 'Weekly Infrastructure Report', priority=4)
