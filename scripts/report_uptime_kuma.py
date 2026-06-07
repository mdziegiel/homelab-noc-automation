#!/usr/bin/env python3
"""
Uptime Kuma digest - daily 8pm ET.
Runs via Hermes cron (no_agent). stdout delivered verbatim to Telegram.
Lists overall up/down counts, flags any DOWN/PENDING/MAINT monitors, and
reports TLS certs nearing expiry. Stdlib only (no pip on VM108).

Reads /metrics with the API key as the basic-auth password (empty username).
"""
import base64, os, re, ssl, time, urllib.request

ENV_PATH = os.path.expanduser("~/.hermes/.env")
TIMEOUT = 12
CERT_WARN_DAYS = 21
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def load_env(path):
    d = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line.rstrip("\n"))
            if m:
                d[m.group(1)] = m.group(2)  # last definition wins (dup blocks)
    return d


def name_of(line):
    m = re.search(r'monitor_name="([^"]*)"', line)
    return m.group(1) if m else None


def val_of(line):
    try:
        return float(line.rsplit("}", 1)[1])
    except (ValueError, IndexError):
        return None


def main():
    E = load_env(ENV_PATH)
    base = E.get("UPTIME_KUMA_URL", "").strip().rstrip("/")
    key = E.get("UPTIME_KUMA_API_KEY", "").strip()
    if not base or not key or key.startswith("<"):
        print("Uptime Kuma digest: UPTIME_KUMA_URL / UPTIME_KUMA_API_KEY not set in .env")
        return
    auth = "Basic " + base64.b64encode(f":{key}".encode()).decode()
    req = urllib.request.Request(f"{base}/metrics", headers={"Authorization": auth})
    try:
        text = urllib.request.urlopen(req, timeout=TIMEOUT, context=CTX).read().decode("utf-8", "replace")
    except Exception as e:
        print(f"Uptime Kuma digest: ERROR reaching {base}/metrics: {type(e).__name__}: {str(e)[:120]}")
        return

    status, rt, cert_days, cert_valid = {}, {}, {}, {}
    for line in text.splitlines():
        if not line or line[0] == "#":
            continue
        n = name_of(line)
        if n is None:
            continue
        v = val_of(line)
        if v is None:
            continue
        if line.startswith("monitor_status{"):
            status[n] = v
        elif line.startswith("monitor_response_time{"):
            rt[n] = v
        elif line.startswith("monitor_cert_days_remaining{"):
            cert_days[n] = v
        elif line.startswith("monitor_cert_is_valid{"):
            cert_valid[n] = v

    if not status:
        print("Uptime Kuma digest: no monitors reported by /metrics")
        return

    SMAP = {0: "DOWN", 1: "UP", 2: "PENDING", 3: "MAINT"}
    up = [k for k, v in status.items() if v == 1]
    down = sorted(k for k, v in status.items() if v == 0)
    other = sorted((k, SMAP.get(v, str(v))) for k, v in status.items() if v not in (0, 1))
    bad_cert = sorted(k for k, v in cert_valid.items() if v == 0)
    exp_soon = sorted((k, cert_days[k]) for k in cert_days if cert_days[k] <= CERT_WARN_DAYS)

    problems = bool(down or other or bad_cert or exp_soon)
    now = time.strftime("%a %Y-%m-%d %H:%M %Z")
    head = "ALL GREEN" if not problems else f"{len(down)+len(other)+len(bad_cert)+len(exp_soon)} item(s) need attention"
    out = [f"Uptime Kuma Digest  -  {now}", "=" * 38, head,
           f"monitors: {len(up)}/{len(status)} up, {len(down)} down"]

    if down:
        out.append("\nDOWN:")
        for k in down:
            out.append(f"  {k}")
    for k, s in other:
        out.append(f"\n{s}: {k}")
    if bad_cert:
        out.append("\nINVALID CERT:")
        for k in bad_cert:
            out.append(f"  {k}")
    if exp_soon:
        out.append(f"\nCERT EXPIRING (<= {CERT_WARN_DAYS}d):")
        for k, d in exp_soon:
            out.append(f"  {k}: {int(d)}d")

    print("\n".join(out))


if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, 'Uptime Kuma Digest', priority=5)
