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
# Database
# ---------------------------------------------------------------------------
# Previously the default arg repeated across database.py, anomaly_detection.py,
# filtering.py, and phase5/backend/app.py.
DB_PATH = os.environ.get("HANNIBAALNS_DB_PATH", "hannibaaldns.db")

# ---------------------------------------------------------------------------
# DoT TLS material (auto-generated self-signed cert; see README)
# ---------------------------------------------------------------------------
CERT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hannibaaldns.crt")
KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hannibaaldns.key")