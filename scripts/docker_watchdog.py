#!/usr/bin/env python3
"""Docker watchdog - checks all containers via Portainer across all endpoints.
Stateful: alerts only on CHANGE (new down/unhealthy, or recovery). Silent when
nothing changed. Empty stdout = no message delivered. Stdlib only (VM108)."""
import os, re, json, ssl, urllib.request, sys, time

ENV = os.path.expanduser('~/.hermes/.env')
STATE = os.path.expanduser('~/.hermes/state/docker_watchdog.json')

def load_env():
    d = {}
    for line in open(ENV, encoding='utf-8', errors='replace'):
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line.rstrip('\n'))
        if m:
            d[m.group(1)] = m.group(2)
    return d

def main():
    E = load_env()
    url = E.get('PORTAINER_URL')
    user = E.get('PORTAINER_USERNAME')
    pw = E.get('PORTAINER_PASSWORD')
    if not (url and user and pw):
        print("DOCKER WATCHDOG: Portainer credentials missing in ~/.hermes/.env")
        return
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

    def req(path, jwt=None, data=None):
        h = {}
        if jwt: h["Authorization"] = "Bearer " + jwt
        if data is not None:
            h["Content-Type"] = "application/json"; data = json.dumps(data).encode()
        r = urllib.request.Request(url + path, data=data, headers=h,
                                   method="POST" if data is not None else "GET")
        return json.loads(urllib.request.urlopen(r, context=ctx, timeout=15).read())

    # --- auth ---
    try:
        jwt = req("/api/auth", data={"Username": user, "Password": pw})["jwt"]
    except Exception as e:
        print(f"DOCKER WATCHDOG: Portainer auth FAILED at {url} -> {e}")
        return

    # --- collect down/unhealthy across all endpoints ---
    problems = {}  # key "endpoint/container" -> human string
    errors = []
    try:
        endpoints = req("/api/endpoints", jwt=jwt)
    except Exception as e:
        print(f"DOCKER WATCHDOG: cannot list endpoints -> {e}")
        return
    for ep in endpoints:
        eid, ename = ep["Id"], ep["Name"]
        try:
            cs = req(f"/api/endpoints/{eid}/docker/containers/json?all=1", jwt=jwt)
        except Exception as e:
            errors.append(f"endpoint '{ename}' unreachable: {e}")
            continue
        for c in cs:
            name = c["Names"][0].lstrip('/')
            state = c.get("State", "?")
            status = c.get("Status", "")
            key = f"{ename}/{name}"
            if state != "running":
                problems[key] = f"{key}: {state} ({status})"
            elif "unhealthy" in status.lower():
                problems[key] = f"{key}: running but UNHEALTHY ({status})"

    # --- load prior state ---
    prev = {}
    try:
        prev = json.load(open(STATE)).get("problems", {})
    except Exception:
        prev = {}

    new_down = {k: v for k, v in problems.items() if k not in prev}
    recovered = [k for k in prev if k not in problems]
    still_down = {k: v for k, v in problems.items() if k in prev}

    # --- persist current state ---
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    json.dump({"ts": int(time.time()), "problems": problems}, open(STATE, "w"), indent=2)

    # --- decide output ---
    lines = []
    if new_down:
        lines.append("DOCKER ALERT - container(s) DOWN/UNHEALTHY:")
        for v in sorted(new_down.values()):
            lines.append("  " + v)
    if recovered:
        lines.append("DOCKER RECOVERED - back to running:")
        for k in sorted(recovered):
            lines.append("  " + k)
    if errors:
        lines.append("DOCKER WATCHDOG degraded:")
        for e in errors:
            lines.append("  " + e)

    # Only speak on change. If nothing new and nothing recovered and no errors -> silent,
    # even if known-down containers persist (already alerted once).
    if lines:
        if still_down and (new_down or recovered):
            lines.append(f"Still down (previously reported): {', '.join(sorted(still_down))}")
        print("\n".join(lines))

if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, 'Docker Watchdog', priority=7)
