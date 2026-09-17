import time
import socket
from dnslib import DNSRecord, QTYPE
from database import Database
from filtering import FilteringEngine
from dns_server import SimpleResolver, DNSServer

# Test configuration
db_path = "test_anomaly_detection.db"
server_host = "127.0.0.1"
server_port = 5054

# Initialize database and engine
print("Initializing test database...")
db = Database(db_path)
engine = FilteringEngine(db_path=db_path)

# Start test DNS server
resolver = SimpleResolver('8.8.8.8', engine)
server = DNSServer(resolver, port=server_port)
server.start_thread()
time.sleep(1)  # Let server thread spin up

try:
    # Helper function to send DNS query
    def send_query(domain, client_ip='127.0.0.1'):
        print(f"Sending query for {domain} from {client_ip}")
        request = DNSRecord.question(domain, qtype='A')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((client_ip, 0))  # Bind to specific client IP
        sock.settimeout(5)
        try:
            sock.sendto(request.pack(), (server_host, server_port))
            data, _ = sock.recvfrom(512)
            response = DNSRecord.parse(data)
            print(f"Response for {domain}: Status {response.header.rcode}")
            return response.header.rcode
        except Exception as e:
            print(f"Error: {e}")
            return None
        finally:
            sock.close()

    # Test 1: Normal query (should not trigger anomaly)
    print("\n=== Test 1: Normal query ===")
    send_query("google.com")
    time.sleep(2)  # Let anomaly detection run

    # Test 2: Long subdomain query (should trigger anomaly)
    print("\n=== Test 2: Long subdomain query ===")
    long_domain = "a" * 51 + ".example.com"
    send_query(long_domain)
    time.sleep(2)  # Let anomaly detection run

    # Test 3: High frequency queries (should trigger anomaly)
    print("\n=== Test 3: High frequency queries ===")
    for _ in range(6):  # More than 5 queries in 1 second
        send_query("frequent.example.com")
        time.sleep(0.1)
    time.sleep(2)  # Let anomaly detection run

    # Test 4: High entropy domain (should trigger anomaly)
    print("\n=== Test 4: High entropy domain ===")
    import random
    import string
    high_entropy_domain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20)) + ".example.com"
    send_query(high_entropy_domain)
    time.sleep(2)  # Let anomaly detection run

finally:
    server.stop()
    print("\nTest completed. Check the output for anomaly detections.")