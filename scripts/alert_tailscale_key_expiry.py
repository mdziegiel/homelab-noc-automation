#!/usr/bin/env python3
"""
Tailscale API key expiry alert - runs daily via Hermes cron (no_agent).

The Tailscale API access key (tskey-api-...) used by this homelab's monitoring
has a fixed 90-day lifetime and is NOT introspectable via the v2 API (the
/devices endpoint exposes node key expiry, not the API access key's). So this
alert tracks the known issue/expiry dates as config and warns ahead of time.

Key created : 2026-06-06
Key expires : 2026-09-04  (90 days)

STATEFUL: only fires once per threshold bucket (30d, 14d, 7d, expired) so it
never nags daily for the same slowly-approaching expiry. Silent otherwise
(empty stdout = no_agent sends nothing).

State: ~/.hermes/state/tailscale_key_expiry.json -> {"last_bucket": "<bucket>"}

When the key is rotated, update KEY_EXPIRY below (and the .env value) and
delete the state file so the bucket baseline resets.
"""
import datetime as dt
import json
import os

STATE = os.path.expanduser("~/.hermes/state/tailscale_key_expiry.json")

# Fixed expiry of the current TAILSCALE_API_KEY (UTC date).
KEY_CREATED = dt.date(2026, 6, 6)
KEY_EXPIRY = dt.date(2026, 9, 4)

# Alert thresholds in days-remaining. Order matters (worst last).
THRESHOLDS = [30, 14, 7]


def bucket(days):
    """Coarse bucket so we alert on transitions, not every day."""
    if days <= 0:
        return "expired"
    if days <= 7:
        return "7d"
    if days <= 14:
        return "14d"
    if days <= 30:
        return "30d"
    return "ok"


ORDER = {"ok": 0, "30d": 1, "14d": 2, "7d": 3, "expired": 4}


def main():
    today = dt.datetime.now(dt.UTC).date()
    days = (KEY_EXPIRY - today).days
    b = bucket(days)

    # load state
    try:
        with open(STATE, encoding="utf-8") as f:
            last = json.load(f).get("last_bucket", "ok")
    except Exception:
        last = "ok"

    # persist current bucket (so a rotation that resets to "ok" re-arms alerts)
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"last_bucket": b, "checked": today.isoformat(),
                   "days_remaining": days}, f)
    os.replace(tmp, STATE)

    # only alert when crossing into a worse bucket than last alerted
    if b == "ok" or ORDER[b] <= ORDER.get(last, 0):
        return  # silent

    exp = KEY_EXPIRY.isoformat()
    if b == "expired":
        print(f"\U0001f534 TAILSCALE API KEY EXPIRED\n"
              f"The Tailscale API key expired on {exp} "
              f"({abs(days)} day(s) ago).\n"
              f"Monitoring that uses TAILSCALE_API_KEY is now BROKEN. "
              f"Rotate the key in the Tailscale admin console, update "
              f"TAILSCALE_API_KEY in ~/.hermes/.env, then update KEY_EXPIRY "
              f"in alert_tailscale_key_expiry.py and delete its state file.")
    else:
        print(f"\u26a0\ufe0f TAILSCALE API KEY EXPIRING\n"
              f"The Tailscale API key expires in {days} day(s) on {exp}.\n"
              f"Rotate it before then or homelab monitoring loses Tailscale "
              f"visibility. After rotating: update TAILSCALE_API_KEY in "
              f"~/.hermes/.env, bump KEY_EXPIRY in this script, and delete "
              f"~/.hermes/state/tailscale_key_expiry.json to re-arm.")


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from notify import deliver
    deliver(main, "Tailscale API Key Expiry", priority=8)
