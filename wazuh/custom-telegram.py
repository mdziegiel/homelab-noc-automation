#!/var/ossec/framework/python/bin/python3
# Wazuh -> Telegram custom integration
# Install: /var/ossec/integrations/custom-telegram.py  (chmod 750, root:wazuh)
# Also needs the wrapper /var/ossec/integrations/custom-telegram (see README)
# hook_url (bot token) + chat_id come from ossec.conf <integration> block.
import sys, json, ssl, os
try:
    import requests
except ImportError:
    requests = None
import urllib.request

# Wazuh's framework python defaults its CA path to /usr/local/ssl/cert.pem,
# which doesn't exist on Ubuntu -> SSL CERTIFICATE_VERIFY_FAILED against
# api.telegram.org. Build a context against the real system CA bundle; fall
# back to an unverified context only if no bundle is found (public API).
def _ssl_ctx():
    for ca in ("/etc/ssl/certs/ca-certificates.crt",
               "/etc/pki/tls/certs/ca-bundle.crt"):
        if os.path.exists(ca):
            return ssl.create_default_context(cafile=ca)
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c

# argv: [script, alert_file, api_key(=chat_id), hook_url, ...]
alert_file = sys.argv[1]
chat_id    = sys.argv[2]            # passed via <api_key> in ossec.conf
hook_url   = sys.argv[3]            # passed via <hook_url> in ossec.conf

with open(alert_file, errors="replace") as f:
    alert = json.load(f)

rule  = alert.get("rule", {})
level = rule.get("level", "?")
desc  = rule.get("description", "n/a")
rid   = rule.get("id", "?")
agent = alert.get("agent", {}).get("name", "?")
srcip = alert.get("data", {}).get("srcip", "")
ts    = alert.get("timestamp", "")

text = (
    f"\U0001F6A8 Wazuh Alert  (level {level})\n"
    f"Rule {rid}: {desc}\n"
    f"Agent: {agent}\n"
    + (f"Source IP: {srcip}\n" if srcip else "")
    + f"Time: {ts}"
)

payload = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
data = json.dumps(payload).encode()
req = urllib.request.Request(
    hook_url, data=data, headers={"Content-Type": "application/json"}
)
try:
    with urllib.request.urlopen(req, timeout=10, context=_ssl_ctx()) as r:
        r.read()
except Exception as e:
    sys.stderr.write(f"custom-telegram error: {e}\n")
    sys.exit(1)
