#!/usr/bin/env python3
"""
Shared notification helper for Homelab cron scripts.

Provides deliver(main_fn, title, priority): runs a script's main() while
capturing its stdout, then:
  1. Re-emits the captured text to the REAL stdout so Hermes' no_agent cron
     delivery to Telegram keeps working exactly as before (empty stdout =
     silent, non-empty = the Telegram message).
  2. ALSO pushes the same text to Gotify as a second notification channel,
     but ONLY when the output is non-empty -- preserving the "silent when
     nothing to report" semantics of the stateful alert scripts.

Gotify is best-effort: a Gotify outage NEVER breaks Telegram delivery or the
script itself. Stdlib only (VM108 has no pip).

.env keys: GOTIFY_URL, GOTIFY_TOKEN.
"""
import contextlib
import io
import os
import re
import sys
import urllib.parse
import urllib.request

ENV_PATH = os.path.expanduser("~/.hermes/.env")
GOTIFY_TIMEOUT = 8


def _load_env(path=ENV_PATH):
    d = {}
    try:
        for line in open(path, encoding="utf-8", errors="replace"):
            m = re.match(r'^([A-Za-z_]\w*)=(.*)$', line.rstrip("\n"))
            if m:
                d[m.group(1)] = m.group(2)  # last-wins
    except Exception:
        pass
    return d


def push_gotify(title, message, priority=5):
    """Best-effort push to Gotify. Returns True on success, False otherwise.
    Never raises."""
    E = _load_env()
    base = E.get("GOTIFY_URL", "").strip().rstrip("/")
    token = E.get("GOTIFY_TOKEN", "").strip()
    if not base or not token or token.startswith("<"):
        return False
    if not (message or "").strip():
        return False  # nothing to send -> stay silent
    try:
        data = urllib.parse.urlencode({
            "title": title,
            "message": message,
            "priority": str(priority),
        }).encode()
        req = urllib.request.Request(
            f"{base}/message?token={urllib.parse.quote(token)}",
            data=data, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        urllib.request.urlopen(req, timeout=GOTIFY_TIMEOUT).read()
        return True
    except Exception as e:
        # Surface to stderr only (stderr is not delivered) so a broken Gotify
        # token is debuggable from the cron run log without polluting Telegram.
        sys.stderr.write(f"[notify] Gotify push failed: "
                         f"{type(e).__name__}: {str(e)[:120]}\n")
        return False


def deliver(main_fn, title, priority=5):
    """Run main_fn, capturing stdout. Re-emit to real stdout (Telegram path),
    then mirror non-empty output to Gotify. main_fn exceptions propagate after
    any partial stdout is flushed (so the cron run is still marked failed)."""
    buf = io.StringIO()
    err = None
    try:
        with contextlib.redirect_stdout(buf):
            main_fn()
    except Exception as e:  # capture, flush what we have, then re-raise
        err = e
    text = buf.getvalue()
    # 1) preserve original Telegram delivery (verbatim stdout)
    if text:
        sys.stdout.write(text)
        sys.stdout.flush()
    # 2) mirror to Gotify (best-effort, non-empty only)
    push_gotify(title, text.strip(), priority)
    if err is not None:
        raise err
