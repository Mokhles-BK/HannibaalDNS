import sys
import socket
import time
import threading
import urllib.request
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, DNSError, RCODE
from dnslib.server import DNSServer, BaseResolver
from filtering import FilteringEngine
from dns_resolver import resolve_query
import config

sys.stdout.reconfigure(line_buffering=True)

class SimpleResolver(BaseResolver):
    def __init__(self, upstream_dns, engine, upstream_port=None):
        self.upstream_dns = upstream_dns
        self.upstream_port = upstream_port
        self.engine = engine

    def resolve(self, request, handler):
        client_ip = handler.client_address[0] if handler else 'unknown'
        raw_request = request.pack()
        return DNSRecord.parse(resolve_query(
            raw_request, client_ip, self.upstream_dns, self.engine,
            self.upstream_port,
        ))

def run_dns_server(upstream_dns=None, port=None, upstream_port=None):
    # Defaults looked up at call time (config may be overridden via env).
    upstream_dns = config.UPSTREAM_DNS if upstream_dns is None else upstream_dns
    port = config.UDP_PORT if port is None else port
    upstream_port = config.UPSTREAM_PORT if upstream_port is None else upstream_port

    engine = FilteringEngine()
    resolver = SimpleResolver(upstream_dns, engine, upstream_port)
    server = DNSServer(resolver, port=port)

    print(f"Starting DNS server on port {port}...")
    print(f"Forwarding unresolved queries to {upstream_dns}")

    # Add a global reference to trigger reload
    def trigger_reload():
        print("Manual reload triggered")
        engine.force_reload()

    threading.Thread(target=lambda: (time.sleep(10), trigger_reload()), daemon=True).start()

    try:
        server.start_thread()
        while server.isAlive():
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
        print("DNS server stopped")
        # Flush any queued log entries before exiting
        if hasattr(engine.db, 'log_queue'):
            engine.db.log_queue.put(None)
            try:
                engine.db.writer_thread.join(timeout=2)
            except AttributeError:
                pass  # No writer thread if not using queue-based logging

if __name__ == '__main__':
    run_dns_server()