#!/usr/bin/env python3
"""
Wazuh high/critical alert digest - last 24h.
Cron: daily 20:00 ET (00:00 UTC during EDT), no_agent.

FULL MODE (preferred): if WAZUH_INDEXER_USER/WAZUH_INDEXER_PASS are set in .env
(and the indexer host is reachable), query wazuh-alerts-* for rule.level>=12
in the last 24h and summarize by severity / rule / agent.

DEGRADED MODE: the Wazuh manager API (4.x) does NOT expose per-alert severity;
that data lives only in the indexer. If indexer creds/reachability are missing,
fall back to a manager-API security posture summary so the daily report still
delivers real signal, and state exactly what to enable for full severity data.

Indexer host resolution order:
  WAZUH_INDEXER_HOST env  ->  https://10.0.0.233:9200
Stdlib only.
"""
import json, re, ssl, os, sys, time, base64, urllib.request
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ENV_PATH = os.path.expanduser("~/.hermes/.env")
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
TIMEOUT = 15
MGR = "https://10.0.0.233:55000"
LEVEL_MIN = 12   # Wazuh rule.level 12-15 = high/critical

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

def tcp_open(host, port, t=3):
    import socket
    try:
        socket.create_connection((host, int(port)), t).close()
        return True
    except Exception:
        return False

# ---------- FULL MODE: indexer ----------
def indexer_digest():
    iu = E.get("WAZUH_INDEXER_USER", "").strip()
    ip = E.get("WAZUH_INDEXER_PASS", "").strip()
    if not iu or not ip:
        return None  # no creds -> degraded
    host = E.get("WAZUH_INDEXER_HOST", "https://10.0.0.233:9200").rstrip("/")
    hp = host.split("://", 1)[-1]
    h, _, p = hp.partition(":")
    if not tcp_open(h, p or "9200"):
        return None  # unreachable -> degraded
    auth = {"Authorization": "Basic " + base64.b64encode(f"{iu}:{ip}".encode()).decode(),
            "Content-Type": "application/json"}
    query = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-24h"}}},
            {"range": {"rule.level": {"gte": LEVEL_MIN}}}]}},
        "aggs": {
            "by_level": {"terms": {"field": "rule.level", "size": 10}},
            "by_rule": {"terms": {"field": "rule.description", "size": 8}},
            "by_agent": {"terms": {"field": "agent.name", "size": 8}}}}
    try:
        res = json.loads(http(f"{host}/wazuh-alerts-*/_search",
                              headers=auth, data=json.dumps(query).encode(), method="POST"))
    except Exception as e:
        return None  # fall back rather than error out
    total = res.get("hits", {}).get("total", {})
    total = total.get("value", total) if isinstance(total, dict) else total
    aggs = res.get("aggregations", {})
    if not total:
        return "\u2705 WAZUH \u2014 no high/critical alerts (rule.level\u226512) in last 24h"
    out = [f"\U0001f6a8 WAZUH \u2014 {total} high/critical alert(s) in last 24h (rule.level\u2265{LEVEL_MIN})"]
    lv = aggs.get("by_level", {}).get("buckets", [])
    if lv:
        out.append("  by level: " + ", ".join(f"L{b['key']}:{b['doc_count']}" for b in lv))
    for b in aggs.get("by_agent", {}).get("buckets", [])[:6]:
        out.append(f"  agent {b['key']}: {b['doc_count']}")
    for b in aggs.get("by_rule", {}).get("buckets", [])[:6]:
        out.append(f"  \u2022 {b['key'][:70]}: {b['doc_count']}")
    return "\n".join(out)

# ---------- DEGRADED MODE: manager API ----------
def manager_jwt():
    u = E.get("WAZUH_API_USER", "YOUR_WAZUH_API_USER"); p = E.get("WAZUH_API_PASSWORD", "")
    return http(f"{MGR}/security/user/authenticate?raw=true",
                {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}
                ).decode().strip()

def manager_digest():
    try:
        jwt = manager_jwt()
    except Exception as e:
        return f"\u26a0\ufe0f WAZUH unreachable: {type(e).__name__}: {str(e)[:100]}"
    hdr = {"Authorization": f"Bearer {jwt}"}
    out = ["\u26a0\ufe0f WAZUH digest (DEGRADED \u2014 manager API only; no per-alert severity)"]
    # agents
    try:
        ag = json.loads(http(f"{MGR}/agents?limit=500", hdr))["data"]["affected_items"]
        active = [a for a in ag if a.get("status") == "active"]
        bad = [a for a in ag if a.get("status") != "active"]
        out.append(f"  agents: {len(active)}/{len(ag)} active" +
                   ("" if not bad else " | DOWN: " +
                    ", ".join(f"{a.get('id')} {a.get('name','')}" for a in bad)))
    except Exception as e:
        out.append(f"  agents: query failed ({type(e).__name__})")
    # analysisd throughput (events decoded / dropped) over current stats window
    try:
        st = json.loads(http(f"{MGR}/manager/stats/analysisd", hdr))["data"]["affected_items"][0]
        out.append(f"  events decoded: {int(st.get('total_events_decoded',0)):,} | "
                   f"alerts written: {int(st.get('alerts_written',0)):,} | "
                   f"events dropped: {int(st.get('events_dropped',0)):,}")
    except Exception:
        pass
    # recent manager error-level logs
    try:
        logs = json.loads(http(f"{MGR}/manager/logs?level=error&limit=200", hdr))["data"]["affected_items"]
        day = time.time() - 86400
        recent = []
        for L in logs:
            ts = L.get("timestamp", "")
            recent.append(L)
        from collections import Counter
        tags = Counter(L.get("tag", "?") for L in logs)
        if logs:
            out.append(f"  manager error logs (recent): {len(logs)} | " +
                       ", ".join(f"{k}:{v}" for k, v in tags.most_common(4)))
    except Exception:
        pass
    out.append("  \u2192 For true high/critical alert severity, add WAZUH_INDEXER_USER / "
               "WAZUH_INDEXER_PASS to .env and allow VM108 to reach the indexer (:9200).")
    return "\n".join(out)

def main():
    full = None
    try:
        full = indexer_digest()
    except Exception:
        full = None
    print(full if full is not None else manager_digest())

if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, 'Wazuh Alert Digest', priority=6)
