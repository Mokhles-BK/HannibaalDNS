import sys
import socket
import time
import threading
import urllib.request
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, DNSError, RCODE
from dnslib.server import DNSServer, BaseResolver
from filtering import FilteringEngine
from dns_resolver import resolve_query

sys.stdout.reconfigure(line_buffering=True)

class SimpleResolver(BaseResolver):
    def __init__(self, upstream_dns, engine):
        self.upstream_dns = upstream_dns
        self.engine = engine

    def resolve(self, request, handler):
        client_ip = handler.client_address[0] if handler else 'unknown'
        raw_request = request.pack()
        return DNSRecord.parse(resolve_query(raw_request, client_ip, self.upstream_dns, self.engine))

def run_dns_server(upstream_dns='8.8.8.8', port=5053):
    engine = FilteringEngine()
    resolver = SimpleResolver(upstream_dns, engine)
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