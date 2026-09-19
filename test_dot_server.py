"""
Self-contained DoT (DNS-over-TLS, port 853) coverage test.

Mirrors verify_live_wiring.py: starts its own dot_server instance in a
background thread, then sends length-prefixed TLS queries and asserts on
the DNS rcode. Proves the DoT path applies the same filtering as UDP/DoH.

    python test_dot_server.py
"""
import os
import socket
import ssl
import sys
import threading
import time

from dnslib import DNSRecord

# Project root on sys.path so dot_server imports resolve.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dot_server

HOST = '127.0.0.1'
PORT = 8553  # non-default to avoid clashing with a running 853 instance
NORMAL_DOMAIN = 'google.com'
BLOCKED_DOMAIN = 'doubleclick.net'  # globally blocked by StevenBlack hosts


def _wait_for_server(host, port, timeout=15):
    """
    Wait until the DoT server answers a TLS handshake.

    Must NOT use a plain TCP probe: the server socket is TLS-wrapped, so
    `accept()` blocks on a TLS handshake that a plain client never sends;
    the probe closing then raises ConnectionError and kills the accept
    loop. Probe with TLS instead.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                                server_hostname='hannibaaldns.local')
            s.settimeout(1)
            s.connect((host, port))
            s.close()
            return True
        except (ConnectionError, OSError, ssl.SSLError):
            time.sleep(0.2)
    return False


def _dot_query(domain, client_cert=None):
    """Send one length-prefixed DNS query over TLS and return the rcode."""
    raw = DNSRecord.question(domain, qtype='A').pack()
    ctx = ssl.create_default_context()
    if client_cert:
        ctx.load_verify_locations(client_cert)
    else:
        # Self-signed test cert: skip verification, like the manual probes.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    s = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                        server_hostname='hannibaaldns.local')
    s.settimeout(8)
    s.connect((HOST, PORT))
    try:
        s.sendall(len(raw).to_bytes(2, 'big') + raw)
        n = int.from_bytes(_recv_exact(s, 2), 'big')
        resp = _recv_exact(s, n)
    finally:
        s.close()
    return DNSRecord.parse(resp).header.rcode


def _recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('server closed the connection')
        buf += chunk
    return buf


def main():
    print(f"=== Testing DoT server on {HOST}:{PORT} ===")

    # 1. Start our own DoT instance (same construction as run_dot_server).
    engine = dot_server.FilteringEngine()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(dot_server.CERT_PATH, dot_server.KEY_PATH)
    plain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    plain.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    plain.bind((HOST, PORT))
    plain.listen(128)
    tls_sock = ctx.wrap_socket(plain, server_side=True)

    def accept_loop():
        # Same tolerance as dot_server.run_dot_server: a probe that opens a
        # TLS handshake then disconnects aborts accept() with
        # ConnectionAbortedError; that is not a shutdown signal, so retry.
        # (ConnectionAbortedError/ConnectionResetError are OSError subclasses,
        # so the narrow ones must be caught first.)
        while True:
            try:
                conn, _ = tls_sock.accept()
            except (ssl.SSLError, ConnectionAbortedError,
                    ConnectionResetError):
                continue
            except OSError:
                return
            threading.Thread(target=dot_server._handle_client,
                             args=(conn, engine, '8.8.8.8'), daemon=True).start()

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()

    if not _wait_for_server(HOST, PORT):
        print("FAIL: DoT server did not come up")
        return 1

    try:
        # 2. Normal domain -> NOERROR (0)
        rc_normal = _dot_query(NORMAL_DOMAIN)
        print(f"DoT query for {NORMAL_DOMAIN} -> rcode {rc_normal} (expected 0)")
        assert rc_normal == 0, f"expected NOERROR, got {rc_normal}"

        # 3. Globally blocked domain -> NXDOMAIN (3)
        rc_blocked = _dot_query(BLOCKED_DOMAIN)
        print(f"DoT query for {BLOCKED_DOMAIN} -> rcode {rc_blocked} (expected 3)")
        assert rc_blocked == 3, f"expected NXDOMAIN, got {rc_blocked}"

        # 4. Same filtering as the UDP path: blocked must differ from allowed.
        assert rc_blocked != rc_normal, "DoT filtering does not differ from allowed"

        # 5. A cert-pinned client (verifying the self-signed cert) also works,
        #    proving the server presents a real, valid TLS certificate.
        rc_pinned = _dot_query(NORMAL_DOMAIN, client_cert=dot_server.CERT_PATH)
        print(f"DoT query (cert-pinned) for {NORMAL_DOMAIN} -> rcode {rc_pinned}")
        assert rc_pinned == 0, "cert-pinned client failed"

        print("\n=== DoT server test PASSED ===")
        return 0
    finally:
        try:
            tls_sock.close()
        except Exception:
            pass
        if hasattr(engine.db, 'log_queue'):
            engine.db.log_queue.put(None)
            try:
                engine.db.writer_thread.join(timeout=2)
            except AttributeError:
                pass


if __name__ == '__main__':
    sys.exit(main())