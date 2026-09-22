"""
Central configuration for HannibaalDNS.

Every value here has a default that matches what was previously hardcoded
across dns_server.py, phase5/backend/app.py, dot_server.py, filtering.py,
database.py, and anomaly_detection.py, so importing this module changes
nothing unless an override is present.

Override any value with an environment variable (HANNIBAALNS_*), e.g.:

    HANNIBAALNS_UPSTREAM_DNS=1.1.1.1 HANNIBAALNS_DNS_PORT=5053 python dns_server.py

No resolution, filtering, or anomaly-detection logic lives here — this is
purely wiring.
"""
import os

# ---------------------------------------------------------------------------
# Upstream resolver
# ---------------------------------------------------------------------------
# Previously '8.8.8.8' in dns_server.py, phase5/backend/app.py, dot_server.py.
UPSTREAM_DNS = os.environ.get("HANNIBAALNS_UPSTREAM_DNS", "8.8.8.8")

# Previously hardcoded to 53 in dns_resolver.resolve_query().
UPSTREAM_PORT = int(os.environ.get("HANNIBAALNS_UPSTREAM_PORT", "53"))

# Upstream query timeout (seconds). A dead upstream must not hang a
# transport: dnslib's DNSRecord.send() uses this as its socket timeout,
# and resolve_query() returns SERVFAIL when it fires. Previously hardcoded
# to 5 in dns_resolver.resolve_query(); 3s is the "within about 3
# seconds" requirement from the v1.0 scope.
UPSTREAM_TIMEOUT = float(os.environ.get("HANNIBAALNS_UPSTREAM_TIMEOUT", "3"))

# ---------------------------------------------------------------------------
# Transport ports
# ---------------------------------------------------------------------------
# Previously hardcoded: UDP 5053, DoH 5000, DoT 853.
UDP_PORT = int(os.environ.get("HANNIBAALNS_UDP_PORT", "5053"))
DOH_PORT = int(os.environ.get("HANNIBAALNS_DOH_PORT", "5000"))
DOT_PORT = int(os.environ.get("HANNIBAALNS_DOT_PORT", "853"))

# ---------------------------------------------------------------------------
# DoT bind address
# ---------------------------------------------------------------------------
# Previously hardcoded '0.0.0.0' in dot_server.run_dot_server().
DOT_BIND_HOST = os.environ.get("HANNIBAALNS_DOT_BIND_HOST", "0.0.0.0")

# ---------------------------------------------------------------------------
# Blocklist source
# ---------------------------------------------------------------------------
# Previously the default arg of FilteringEngine.__init__ in filtering.py.
BLOCKLIST_URL = os.environ.get(
    "HANNIBAALNS_BLOCKLIST_URL",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
)

# ---------------------------------------------------------------------------
# Named blocklist presets (step 5a)
# ---------------------------------------------------------------------------
# Convenience shortcuts surfaced in the UI. Every URL below was verified with
# `curl -sI` and returned HTTP 200 at the time of writing. They are NOT a
# whitelist: the blocklist registry accepts any http(s) URL a user submits,
# checked live before acceptance. See BLOCKLIST_URL above for the default.
#
# Format notes (relevant once parsing is implemented):
#   - StevenBlack: hosts format (0.0.0.0 domain)
#   - OISD:       adblock format (||domain^)
#   - HaGeZi:     dnsmasq format (plain "# domain"), also adblock format
#   - AdGuard:    adblock format (||domain^)
BLOCKLIST_PRESETS = {
    "stevenblack": {
        "name": "StevenBlack hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "format": "hosts",
    },
    "oisd_small": {
        "name": "OISD small",
        "url": "https://small.oisd.nl",
        "format": "adblock",
    },
    "oisd_big": {
        "name": "OISD big",
        "url": "https://big.oisd.nl",
        "format": "adblock",
    },
    "hagezi_light": {
        "name": "HaGeZi Multi LIGHT",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/dnsmasq/light.txt",
        "format": "dnsmasq",
    },
    "hagezi_multi": {
        "name": "HaGeZi Multi NORMAL",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/dnsmasq/multi.txt",
        "format": "dnsmasq",
    },
    "adguard_base": {
        "name": "AdGuard DNS filter (base)",
        "url": "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/general_url.txt",
        "format": "adblock",
    },
}

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# Previously the default arg repeated across database.py, anomaly_detection.py,
# filtering.py, and phase5/backend/app.py.
DB_PATH = os.environ.get("HANNIBAALNS_DB_PATH", "hannibaaldns.db")

# How long query_log/anomaly_log rows are kept before the background
# retention thread purges them (step 6). 0 disables automatic purging;
# the manual POST /api/logs/purge endpoint still works regardless.
LOG_RETENTION_DAYS = int(os.environ.get("HANNIBAALNS_LOG_RETENTION_DAYS", "30"))

# ---------------------------------------------------------------------------
# DoT TLS material (auto-generated self-signed cert; see README)
# ---------------------------------------------------------------------------
CERT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hannibaaldns.crt")
KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hannibaaldns.key")