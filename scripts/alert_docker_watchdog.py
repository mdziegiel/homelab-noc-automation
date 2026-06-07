#!/usr/bin/env python3
"""
Docker watchdog via Portainer - every 15m, no_agent.
Stateful: alerts only when a container that was RUNNING last check is no longer
running (unexpected stop/crash/unhealthy), and once when it recovers. Containers
that are already-known stopped do NOT re-alert every cycle.
State file: ~/.hermes/state/docker_watchdog.json
Stdlib only.
"""
import json, re, ssl, os, sys, urllib.request
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ENV_PATH = os.path.expanduser("~/.hermes/.env")
STATE = os.path.expanduser("~/.hermes/state/docker_watchdog.json")
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
TIMEOUT = 15

def load_env(p):
    d = {}
    for line in open(p, encoding="utf-8", errors="replace"):
        m = re.match(r'^([A-Za-z_]\w*)=(.*)$', line.rstrip("\n"))
        if m: d[m.group(1)] = m.group(2)
    return d
E = load_env(ENV_PATH)

def http(url, headers=None, data=None, method=None):
    if isinstance(data, dict):
        data = json.dumps(data).encode()
        headers = dict(headers or {}); headers.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    return urllib.request.urlopen(r, timeout=TIMEOUT, context=CTX).read()

def jget(url, headers=None, data=None, method=None):
    return json.loads(http(url, headers, data, method))

def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {}

def save_state(s):
    tmp = STATE + ".tmp"; json.dump(s, open(tmp, "w")); os.replace(tmp, STATE)

def main():
    base = E.get("PORTAINER_URL", "").strip().rstrip("/")
    user = E.get("PORTAINER_USERNAME", "").strip()
    pw = E.get("PORTAINER_PASSWORD", "").strip()
    if not base or not user or not pw:
        print("\u26a0\ufe0f DOCKER WATCHDOG: Portainer credentials not set in .env")
        return
    try:
        jwt = jget(f"{base}/api/auth", data={"Username": user, "Password": pw}, method="POST")["jwt"]
        auth = {"Authorization": f"Bearer {jwt}"}
        endpoints = jget(f"{base}/api/endpoints", auth)
    except Exception as e:
        print(f"\u26a0\ufe0f DOCKER WATCHDOG: Portainer auth/enumerate failed: "
              f"{type(e).__name__}: {str(e)[:120]}")
        return

    cur = {}   # "env/name" -> {"state","status","env"}
    reach_fail = []
    for ep in endpoints:
        epid = ep.get("Id"); epname = ep.get("Name", str(epid))
        try:
            cs = jget(f"{base}/api/endpoints/{epid}/docker/containers/json?all=1", auth)
        except Exception as e:
            reach_fail.append(f"{epname} ({type(e).__name__})")
            continue
        for c in cs:
            name = (c.get("Names", ["?"])[0] or "?").lstrip("/")
            key = f"{epname}/{name}"
            status = c.get("Status", "")
            state = c.get("State", "")
            healthy_bad = "unhealthy" in status.lower()
            # treat unhealthy as not-good even if 'running'
            good = (state == "running") and not healthy_bad
            cur[key] = {"good": good, "state": state, "status": status, "env": epname, "name": name}

    prev = load_state()
    newly_down, recovered = [], []
    for key, info in cur.items():
        was = prev.get(key, {}).get("good")
        now = info["good"]
        if was is True and now is False:
            newly_down.append(info)
        elif was is False and now is True:
            recovered.append(info)

    # persist (keep reach_fail out of state so a transient blip doesn't wipe history)
    if not reach_fail or cur:
        save_state(cur)

    out = []
    if reach_fail:
        out.append("\u26a0\ufe0f DOCKER WATCHDOG: environment(s) unreachable: " + ", ".join(reach_fail))
    if newly_down:
        out.append(f"\U0001f534 CONTAINER DOWN \u2014 {len(newly_down)} container(s)")
        for i in sorted(newly_down, key=lambda x: x["name"]):
            out.append(f"  [{i['env']}] {i['name']}: {i['status'] or i['state']}")
    if recovered:
        out.append(f"\u2705 CONTAINER RECOVERED \u2014 {len(recovered)}")
        for i in sorted(recovered, key=lambda x: x["name"]):
            out.append(f"  [{i['env']}] {i['name']}")
    if out:
        print("\n".join(out))   # else silent

if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, 'Docker Watchdog', priority=7)
