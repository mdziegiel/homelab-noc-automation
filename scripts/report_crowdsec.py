#!/usr/bin/env python3
"""
CrowdSec digest - daily 20:00 ET (00:00 UTC during EDT), no_agent.
Reports:
  - total active bans (decisions)
  - new LOCAL behavioral detections in last 24h (via watcher /v1/alerts, machine auth)
  - bouncer status (best-effort; LAPI /v1/bouncers needs admin and may be 404 remotely)
Stdlib only.
"""
import json, re, ssl, os, sys, urllib.request
from collections import Counter
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ENV_PATH = os.path.expanduser("~/.hermes/.env")
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
TIMEOUT = 15
BASE = "http://10.0.0.237:18080"

def load_env(p):
    d = {}
    for line in open(p, encoding="utf-8", errors="replace"):
        m = re.match(r'^([A-Za-z_]\w*)=(.*)$', line.rstrip("\n"))
        if m: d[m.group(1)] = m.group(2)
    return d
E = load_env(ENV_PATH)

def http(url, headers=None, data=None, method=None):
    r = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    return urllib.request.urlopen(r, timeout=TIMEOUT, context=CTX).read()

def jget(url, headers=None, data=None, method=None):
    return json.loads(http(url, headers, data, method))

def main():
    out = ["\U0001f6e1\ufe0f CROWDSEC digest (24h)"]
    apikey = E.get("CROWDSEC_API_KEY", "")

    # --- total active bans via bouncer LAPI key ---
    total_bans = None
    try:
        dec = jget(f"{BASE}/v1/decisions", {"X-Api-Key": apikey})
        if isinstance(dec, list):
            total_bans = len(dec)
            by_origin = Counter(d.get("origin", "?") for d in dec)
            local = [d for d in dec if d.get("origin") not in ("lists", "CAPI")]
            out.append(f"  active bans: {total_bans:,}  ("
                       + ", ".join(f"{k}:{v}" for k, v in by_origin.most_common(4)) + ")")
            if local:
                scen = Counter(d.get("scenario", "?") for d in local)
                out.append(f"  local-engine bans: {len(local):,}  top: "
                           + ", ".join(f"{k.split('/')[-1]}:{v}" for k, v in scen.most_common(4)))
    except Exception as e:
        out.append(f"  decisions query failed: {type(e).__name__}: {str(e)[:80]}")

    # --- new LOCAL detections (alerts) last 24h via machine/watcher auth ---
    tok = None
    mu = E.get("CROWDSEC_MACHINE_USER", ""); mp = E.get("CROWDSEC_MACHINE_PASS", "")
    if mu and mp:
        try:
            tok = jget(f"{BASE}/v1/watchers/login",
                       {"Content-Type": "application/json"},
                       json.dumps({"machine_id": mu, "password": mp}).encode(), "POST")["token"]
            hdr = {"Authorization": "Bearer " + tok}
            # alerts excluding CAPI/list-sourced -> genuine local detections
            alerts = jget(f"{BASE}/v1/alerts?since=24h&limit=500", hdr)
            if isinstance(alerts, list):
                # Genuine local detections are IP/Range scoped with a crowdsecurity/* scenario.
                # Exclude blocklist/list refreshes ("update : +N/-0 IPs", scope *blocklist*/lists:*).
                def is_local(a):
                    scope = (a.get("source", {}) or {}).get("scope", "") or ""
                    scen = a.get("scenario", "") or ""
                    if scen.startswith("update :"):
                        return False
                    if scope not in ("Ip", "Range"):
                        return False
                    return True
                local_alerts = [a for a in alerts if is_local(a)]
                scen = Counter((a.get("scenario", "?") or "?") for a in local_alerts)
                out.append(f"  new local detections (24h): {len(local_alerts)}")
                for k, v in scen.most_common(6):
                    if k and k != "?":
                        out.append(f"    \u2022 {k.split('/')[-1]}: {v}")
        except Exception as e:
            out.append(f"  watcher alerts unavailable: {type(e).__name__}: {str(e)[:80]}")
    else:
        out.append("  (machine creds not set - skipping new-detection feed)")

    # --- bouncer status (best effort) ---
    got_bouncers = False
    if tok:
        try:
            b = jget(f"{BASE}/v1/bouncers", {"Authorization": "Bearer " + tok})
            if isinstance(b, list):
                got_bouncers = True
                alive = sum(1 for x in b if x.get("last_pull"))
                out.append(f"  bouncers: {len(b)} registered, {alive} active")
                for x in b:
                    out.append(f"    {x.get('name','?')}: "
                               f"{'OK' if x.get('last_pull') else 'no pull'}")
        except Exception:
            pass
    if not got_bouncers:
        out.append("  bouncers: status endpoint not exposed remotely (expected: "
                   "firewall, cloudflare, nginx) - check `cscli bouncers list` on host")
    print("\n".join(out))

if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, 'CrowdSec Digest', priority=5)
