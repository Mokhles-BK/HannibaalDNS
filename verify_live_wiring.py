import time
import socket
import sqlite3
from dnslib import DNSRecord, QTYPE
from database import Database
from filtering import FilteringEngine
from dns_server import SimpleResolver, DNSServer

def test_live_server_client_ip_wiring():
    print("=== Testing Live Server Client IP Wiring ===")

    db_path = "live_test.db"
    import os
    if os.path.exists(db_path):
        os.remove(db_path)

    # 1. Setup Database and Profiles directly in DB
    db = Database(db_path)
    client_ip_a = "127.0.0.2"
    client_ip_b = "127.0.0.3"

    # Profile A blocks 'ads.example.com'
    db.set_profile(client_ip_a, "profile_a", custom_blocklist=["ads.example.com"])
    # Profile B allows 'ads.example.com'
    db.set_profile(client_ip_b, "profile_b", custom_allowlist=["ads.example.com"])

    # 2. Start a test instance of DNSServer on port 5054 using our SimpleResolver
    engine = FilteringEngine(db_path=db_path)
    resolver = SimpleResolver('8.8.8.8', engine)
    server = DNSServer(resolver, port=5054)
    server.start_thread()
    time.sleep(1) # Let server thread spin up

    try:
        # 3. Send queries originating from different local loopback IPs by binding the client socket!
        # This proves handler.client_address captures the exact source IP of the packet.

        def query_from_ip(src_ip, domain):
            req = DNSRecord.question(domain, qtype='A')
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((src_ip, 0)) # Bind client socket to specific source IP
            sock.settimeout(3)
            try:
                sock.sendto(req.pack(), ('127.0.0.1', 5054))
                data, _ = sock.recvfrom(512)
                resp = DNSRecord.parse(data)
                return resp.header.rcode
            finally:
                sock.close()

        # Query ads.example.com from client_ip_a (127.0.0.2) -> should be NXDOMAIN (3)
        res_a = query_from_ip(client_ip_a, "ads.example.com")
        print(f"Query from {client_ip_a} for ads.example.com -> RCODE: {res_a} (Expected: 3 [NXDOMAIN])")

        # Query ads.example.com from client_ip_b (127.0.0.3) -> should be forwarded (0 or whatever upstream returns, not NXDOMAIN due to custom block)
        res_b = query_from_ip(client_ip_b, "ads.example.com")
        print(f"Query from {client_ip_b} for ads.example.com -> RCODE: {res_b} (Expected: not 3, since allowed)")

        assert res_a == 3, f"Client A ({client_ip_a}) should have received NXDOMAIN"
        assert res_b != 3, f"Client B ({client_ip_b}) should NOT have received NXDOMAIN"

        # Wait a bit to allow logs to be processed
        time.sleep(2)

        # 4. Check query logs to ensure handler.client_address correctly passed the source IP into database logging
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT client_ip, domain, blocked FROM query_log ORDER BY id ASC")
        logs = cursor.fetchall()
        conn.close()

        print("\n--- QUERY LOGS RECORDED BY SERVER ---")
        for log in logs:
            print(f"Client IP: {log[0]} | Domain: {log[1]} | Blocked: {log[2]}")

        assert any(l[0] == client_ip_a and l[1] == "ads.example.com" and l[2] == 1 for l in logs), "Missing log for client A"
        assert any(l[0] == client_ip_b and l[1] == "ads.example.com" and l[2] == 0 for l in logs), "Missing log for client B"

        print("\n=== Live Server Client IP Wiring Verification PASSED Successfully ===")

    finally:
        # Flush any queued log entries before stopping the server
        if hasattr(engine.db, 'log_queue'):
            engine.db.log_queue.put(None)
            try:
                engine.db.writer_thread.join(timeout=2)
            except AttributeError:
                pass  # No writer thread if not using queue-based logging

        server.stop()

if __name__ == '__main__':
    test_live_server_client_ip_wiring()