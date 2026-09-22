"""
Smoke test: query every transport and every dashboard endpoint against
already-running servers. Exits non-zero on any failure.

Starts nothing itself. Run after launching the three transports:

    python dns_server.py                 # UDP  5053
    python phase5/backend/app.py         # DoH  5000 (dashboard API too)
    python dot_server.py                 # DoT  853

    python smoke_all.py

Defaults match config.py (UDP 5053, DoH 5000, DoT 853). Override with
HANNIBAALNS_UDP_PORT / HANNIBAALNS_DOH_PORT / HANNIBAALNS_DOT_PORT if your
servers are on other ports, or pass the ports positionally:

    python smoke_all.py 5056 5057 8557

Add --dead-upstream to also assert every transport returns SERVFAIL
(rcode 2) within the configured timeout for an unresolvable domain.
"""
import os
import socket
import ssl
import sys
import urllib.error
import urllib.request

from dnslib import DNSRecord

import config

UDP_PORT = config.UDP_PORT
DOH_PORT = config.DOH_PORT
DOT_PORT = config.DOT_PORT
DOT_HOST = "127.0.0.1"

# (domain, expected rcode) — doubleclick.net is globally blocked.
QUERIES = [
    ("google.com", 0),
    ("doubleclick.net", 3),
]

DASHBOARD_ENDPOINTS = [
    "/api/stats",
    "/api/queries?limit=5",
    "/api/anomalies?limit=5",
    "/api/clients",
    "/api/clients/127.0.0.1/lists",
    "/api/analytics/summary",
    "/api/analytics/top-domains?blocked=false&limit=5",
    "/api/analytics/top-domains?blocked=true&limit=5",
]

# Dead-upstream behaviour: a query for an unresolvable domain must return
# SERVFAIL (rcode 2) within the configured timeout, never hang.
DEAD_DOMAIN = "zzdeadupstream.example.com"
DEAD_EXPECTED_RCODE = 2
DEAD_TIMEOUT = config.UPSTREAM_TIMEOUT + 2  # allow a little slack

failures = []


def fail(msg):
    print(f"  FAIL: {msg}")
    failures.append(msg)


def udp_query(domain, expected_rcode, timeout=5):
    req = DNSRecord.question(domain, qtype="A").pack()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(req, ("127.0.0.1", UDP_PORT))
        data, _ = s.recvfrom(512)
    except Exception as e:
        fail(f"UDP {domain}: {type(e).__name__}: {e}")
        return
    finally:
        s.close()
    rcode = DNSRecord.parse(data).header.rcode
    if rcode != expected_rcode:
        fail(f"UDP {domain}: rcode {rcode}, expected {expected_rcode}")
    else:
        print(f"  ok  UDP {domain} -> rcode {rcode}")


def doh_query(domain, expected_rcode, timeout=5):
    req = DNSRecord.question(domain, qtype="A").pack()
    import base64
    b = base64.urlsafe_b64encode(req).decode().rstrip("=")
    url = f"http://127.0.0.1:{DOH_PORT}/dns-query?dns={b}"
    try:
        r = urllib.request.urlopen(url, timeout=timeout)
        data = r.read()
    except Exception as e:
        fail(f"DoH {domain}: {type(e).__name__}: {e}")
        return
    rcode = DNSRecord.parse(data).header.rcode
    if rcode != expected_rcode:
        fail(f"DoH {domain}: rcode {rcode}, expected {expected_rcode}")
    else:
        print(f"  ok  DoH {domain} -> rcode {rcode}")


def dot_query(domain, expected_rcode, timeout=8):
    raw = DNSRecord.question(domain, qtype="A").pack()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                        server_hostname="hannibaaldns.local")
    s.settimeout(timeout)
    try:
        s.connect((DOT_HOST, DOT_PORT))
        s.sendall(len(raw).to_bytes(2, "big") + raw)
        n = int.from_bytes(_recv_exact(s, 2), "big")
        resp = _recv_exact(s, n)
    except Exception as e:
        fail(f"DoT {domain}: {type(e).__name__}: {e}")
        try:
            s.close()
        except Exception:
            pass
        return
    finally:
        try:
            s.close()
        except Exception:
            pass
    rcode = DNSRecord.parse(resp).header.rcode
    if rcode != expected_rcode:
        fail(f"DoT {domain}: rcode {rcode}, expected {expected_rcode}")
    else:
        print(f"  ok  DoT {domain} -> rcode {rcode}")


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("server closed the connection")
        buf += chunk
    return buf


def dashboard_endpoint(path):
    url = f"http://127.0.0.1:{DOH_PORT}{path}"
    try:
        r = urllib.request.urlopen(url, timeout=5)
        body = r.read()
        status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read()
    except Exception as e:
        fail(f"{path}: {type(e).__name__}: {e}")
        return
    if status != 200:
        fail(f"{path}: HTTP {status}")
    else:
        print(f"  ok  GET {path} -> HTTP {status} ({len(body)} bytes)")


def check_dead_upstream():
    """Assert every transport returns SERVFAIL for a dead upstream."""
    print("=== Dead-upstream SERVFAIL (rcode 2) ===")
    udp_query(DEAD_DOMAIN, DEAD_EXPECTED_RCODE, timeout=DEAD_TIMEOUT)
    doh_query(DEAD_DOMAIN, DEAD_EXPECTED_RCODE, timeout=DEAD_TIMEOUT)
    dot_query(DEAD_DOMAIN, DEAD_EXPECTED_RCODE, timeout=DEAD_TIMEOUT)


def main():
    # Allow port overrides on the command line so smoke_all.py can test
    # servers on non-default ports (e.g. when a stale instance already
    # occupies the default). Positional args: udp_port doh_port dot_port.
    global UDP_PORT, DOH_PORT, DOT_PORT
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) >= 3:
        UDP_PORT = int(args[0])
        DOH_PORT = int(args[1])
        DOT_PORT = int(args[2])

    dead_mode = "--dead-upstream" in sys.argv

    print(f"Smoke test against UDP {UDP_PORT}, DoH {DOH_PORT}, DoT {DOT_PORT}")
    print("=== Transports ===")
    if not dead_mode:
        # In --dead-upstream mode the upstream is unreachable, so a normal
        # query legitimately returns SERVFAIL — skip it and assert the
        # SERVFAIL behaviour explicitly instead.
        for domain, expected in QUERIES:
            udp_query(domain, expected)
            doh_query(domain, expected)
            dot_query(domain, expected)
    else:
        check_dead_upstream()

    print("=== Dashboard API ===")
    for path in DASHBOARD_ENDPOINTS:
        dashboard_endpoint(path)

    if failures:
        print(f"\nSMOKE FAILED: {len(failures)} failure(s)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nSMOKE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())