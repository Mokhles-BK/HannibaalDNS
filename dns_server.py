import sys
import socket
import time
import threading
import urllib.request
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, DNSError, RCODE
from dnslib.server import DNSServer, BaseResolver
from filtering import FilteringEngine

sys.stdout.reconfigure(line_buffering=True)

class SimpleResolver(BaseResolver):
    def __init__(self, upstream_dns, engine):
        self.upstream_dns = upstream_dns
        self.engine = engine

    def resolve(self, request, handler):
        client_ip = handler.client_address[0] if handler else 'unknown'
        qname = str(request.q.qname).rstrip('.')

        # Check filtering engine
        start_time = time.time()
        blocked = self.engine.is_blocked(qname, client_ip)
        response_time = time.time() - start_time

        if blocked:
            print(f"Blocking {qname} for {client_ip}")
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            self.engine.db.log_query(client_ip, qname, QTYPE[request.q.qtype], True, response_time)
            return reply

        reply = request.reply()
        # Forward the query to the upstream DNS server
        try:
            upstream_request = DNSRecord.question(qname, qtype=QTYPE[request.q.qtype])
            raw_response = upstream_request.send(self.upstream_dns, 53, timeout=5)
            upstream_response = DNSRecord.parse(raw_response)

            # Set the transaction ID to match the request
            reply.header.id = request.header.id

            if upstream_response:
                # Copy answer records directly from upstream response
                for rr in upstream_response.rr:
                    reply.add_answer(rr)

            response_time = time.time() - start_time
            self.engine.db.log_query(client_ip, qname, QTYPE[request.q.qtype], False, response_time)
        except Exception as e:
            print(f"Error forwarding DNS query: {e}")
            # Return SERVFAIL if there's an error
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            response_time = time.time() - start_time
            self.engine.db.log_query(client_ip, qname, QTYPE[request.q.qtype], False, response_time)

        return reply

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