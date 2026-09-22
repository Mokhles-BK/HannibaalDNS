"""
Port conflict guard: try a plain bind (no SO_REUSEADDR) on the given
ports before starting any server. If the bind fails, another process
is already holding the port — exit non-zero with a clear message.

Windows allows multiple processes to bind the same UDP port when
SO_REUSEADDR is set, which causes silent query hijacking. This
pre-check catches that scenario.
"""
import socket
import sys


def check_port_free(port: int, proto: str = 'tcp') -> None:
    """
    Try to bind to a port without SO_REUSEADDR.
    Raises SystemExit(1) with a message if the port is already in use.
    """
    sock_type = socket.SOCK_DGRAM if proto == 'udp' else socket.SOCK_STREAM
    s = socket.socket(socket.AF_INET, sock_type)
    # Do NOT set SO_REUSEADDR — we want the bind to fail if the port is taken
    try:
        s.bind(('0.0.0.0', port))
    except OSError as e:
        if e.winerror == 10048 or e.errno == 98:  # WSAEADDRINUSE / EADDRINUSE
            sys.exit(f"port {port} already in use ({proto.upper()})")
        raise
    finally:
        s.close()


def check_all_ports(udp_port: int = 5053, doh_port: int = 5000, dot_port: int = 853) -> None:
    """Check all three transport ports."""
    check_port_free(udp_port, 'udp')
    check_port_free(doh_port, 'tcp')
    check_port_free(dot_port, 'tcp')


if __name__ == '__main__':
    # Allow: python port_check.py [udp_port] [doh_port] [dot_port]
    import sys
    udp = int(sys.argv[1]) if len(sys.argv) > 1 else 5053
    doh = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    dot = int(sys.argv[3]) if len(sys.argv) > 3 else 853
    check_all_ports(udp, doh, dot)
    print(f"All ports free: UDP {udp}, DoH {doh}, DoT {dot}")