"""
DNS-over-TLS (RFC 7858) endpoint on port 853.

Wraps a plain TCP socket in TLS and reuses the shared resolve_query()
logic from dns_resolver.py, so DoT applies exactly the same filtering,
per-client profiles, and query logging as UDP and DoH.

Message framing is the standard 2-byte length prefix per RFC 7766
(TCP transport for DNS) and RFC 1035 Section 4.2.2 (message length
prefix for TCP):
    [0] [1] [2] ... [N]
    uint16 length (big-endian) followed by that many bytes of DNS message.

Usage:
    python dot_server.py                # default: 0.0.0.0:853, 8.8.8.8
    python dot_server.py 1.1.1.1 9053   # custom upstream + port
"""
import os
import sys
import ssl
import socket
import threading
import time
import traceback

from dnslib import DNSError
from filtering import FilteringEngine
from dns_resolver import resolve_query
import config

sys.stdout.reconfigure(line_buffering=True)

CERT_PATH = config.CERT_PATH
KEY_PATH = config.KEY_PATH


def _generate_self_signed_cert(cert_path, key_path):
    """Create a self-signed cert+key if one does not already exist."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DZ"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HannibaalDNS"),
        x509.NameAttribute(NameOID.COMMON_NAME, "hannibaaldns.local"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        # SAN is required for hostname verification. Modern TLS clients do
        # NOT fall back to the CN when SAN is absent, so a cert with only a
        # CN is rejected even when the client otherwise trusts it.
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("hannibaaldns.local")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    print(f"Generated self-signed TLS cert: {cert_path}")


def _ensure_cert(cert_path, key_path):
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        try:
            _generate_self_signed_cert(cert_path, key_path)
        except ImportError:
            # Fall back to openssl CLI if the cryptography package is missing.
            # Use a config file rather than -subj: the shell can mangle a
            # -subj '/CN=...' argument on some platforms (Git Bash in
            # particular parses the leading slash as a path).
            cnf = os.path.join(os.path.dirname(cert_path), "hannibaaldns.cnf")
            with open(cnf, "w") as f:
                f.write(
                    "[req]\n"
                    "distinguished_name = dn\n"
                    # req_extensions is what carries extensions into the CSR;
                    # x509_extensions is what -x509 applies to the issued cert.
                    # Both are needed for SAN to survive a self-signed -x509 build.
                    "req_extensions = v3\n"
                    "x509_extensions = v3\n"
                    "prompt = no\n"
                    "[dn]\nCN = hannibaaldns.local\n"
                    "[alt_names]\nDNS.1 = hannibaaldns.local\n"
                    "[v3]\n"
                    "basicConstraints = critical, CA:TRUE\n"
                    "keyUsage = critical, digitalSignature, keyEncipherment\n"
                    "extendedKeyUsage = serverAuth\n"
                    "subjectAltName = @alt_names\n"
                )
            os.system(
                f"openssl req -x509 -newkey rsa:2048 -keyout {key_path} "
                f"-out {cert_path} -days 3650 -nodes -config {cnf} -sha256 2>/dev/null"
            )
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        raise RuntimeError(
            "Could not obtain a TLS certificate/key for DoT. "
            "Install the 'cryptography' package or openssl, then retry."
        )


def _handle_client(conn, engine, upstream_dns, upstream_port):
    """Read one or more length-prefixed DNS messages from a TLS socket."""
    client_ip = conn.getpeername()[0]
    try:
        buf = b''
        while True:
            try:
                while len(buf) < 2:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                length = int.from_bytes(buf[:2], 'big')
                buf = buf[2:]
                while len(buf) < length:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                message = buf[:length]
                buf = buf[length:]

                response = resolve_query(message, client_ip, upstream_dns, engine,
                                         upstream_port)
                conn.sendall(len(response).to_bytes(2, 'big') + response)
            except (ConnectionError, OSError, DNSError) as e:
                print(f"DoT client {client_ip} disconnected: {e}")
                return
    except Exception:
        # Never let a handler thread die silently: log the traceback and
        # close the connection below. A bare TypeError here used to strand
        # the client with no output and no traceback.
        print(f"DoT client {client_ip} handler error:")
        traceback.print_exc()
    finally:
        try:
            conn.close()
        except Exception:
            pass


def run_dot_server(upstream_dns=None, port=None, host=None, upstream_port=None):
    # Defaults evaluated at call time, not definition time — avoids the
    # classic Python default-argument trap where config values were
    # frozen at import time.
    upstream_dns = config.UPSTREAM_DNS if upstream_dns is None else upstream_dns
    port = config.DOT_PORT if port is None else port
    host = config.DOT_BIND_HOST if host is None else host
    upstream_port = config.UPSTREAM_PORT if upstream_port is None else upstream_port

    _ensure_cert(config.CERT_PATH, config.KEY_PATH)

    engine = FilteringEngine()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(config.CERT_PATH, config.KEY_PATH)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(128)
    tls_sock = ctx.wrap_socket(sock, server_side=True)

    print(f"Starting DNS-over-TLS server on {host}:{port} (upstream {upstream_dns})")
    print(f"TLS cert: {CERT_PATH}")

    try:
        while True:
            try:
                conn, addr = tls_sock.accept()
            except (ConnectionError, OSError):
                continue
            threading.Thread(
                target=_handle_client,
                args=(conn, engine, upstream_dns, upstream_port),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\nDoT server shutting down...")
        if hasattr(engine.db, 'log_queue'):
            engine.db.log_queue.put(None)
            try:
                engine.db.writer_thread.join(timeout=2)
            except AttributeError:
                pass
        tls_sock.close()
        print("DoT server stopped")


if __name__ == '__main__':
    upstream = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    up = int(sys.argv[3]) if len(sys.argv) > 3 else None
    run_dot_server(upstream, p, None, up)