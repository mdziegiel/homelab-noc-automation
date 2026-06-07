#!/usr/bin/env python3
"""
AdGuard Home stats - daily 20:00 ET (00:00 UTC during EDT), no_agent.
Reports query count, block rate, and top blocked domains.
Stdlib only.
"""
import json, re, ssl, os, sys, base64, urllib.request
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ENV_PATH = os.path.expanduser("~/.hermes/.env")
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
TIMEOUT = 15
BASE = "http://10.0.0.21"
USER = "mdziegiel"

def load_env(p):
    d = {}
    for line in open(p, encoding="utf-8", errors="replace"):
        m = re.match(r'^([A-Za-z_]\w*)=(.*)$', line.rstrip("\n"))
        if m: d[m.group(1)] = m.group(2)
    return d
E = load_env(ENV_PATH)

def main():
    auth = {"Authorization": "Basic " + base64.b64encode(
        f"{USER}:{E.get('ADGUARD_PASSWORD','')}".encode()).decode()}
    try:
        s = json.loads(urllib.request.urlopen(urllib.request.Request(
            f"{BASE}/control/stats", headers=auth), timeout=TIMEOUT, context=CTX).read())
    except Exception as e:
        print(f"\u26a0\ufe0f ADGUARD unreachable: {type(e).__name__}: {str(e)[:120]}")
        return
    tot = s.get("num_dns_queries", 0)
    blk = s.get("num_blocked_filtering", 0)
    malware = s.get("num_replaced_safebrowsing", 0)
    pct = (100.0 * blk / tot) if tot else 0.0
    avg = s.get("avg_processing_time", 0) * 1000
    out = [f"\U0001f6e1\ufe0f ADGUARD stats",
           f"  queries: {tot:,}   blocked: {blk:,} ({pct:.1f}%)",
           f"  malware/phishing blocked: {malware:,}   avg latency: {avg:.1f} ms"]
    top_blk = s.get("top_blocked_domains", [])[:10]
    if top_blk:
        out.append("  top blocked domains:")
        for d in top_blk:
            name, cnt = next(iter(d.items()))
            out.append(f"    {name}: {cnt:,}")
    print("\n".join(out))

if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, 'AdGuard Stats', priority=3)
