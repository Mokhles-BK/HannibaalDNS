import socket
import time
from dnslib import DNSRecord, QTYPE
from database import Database

# Test configuration
db_path = "test_hannibaaldns.db"
server_host = "127.0.0.1"
server_port = 5053

# Client profiles
client1_ip = "192.168.1.100"
client2_ip = "192.168.1.101"

# Test domains
test_domain = "reddit.com"
normal_domain = "google.com"

# Initialize database
print("Initializing test database...")
db = Database(db_path)

# Set up client profiles
db.set_profile(client1_ip, "strict", custom_blocklist=["reddit.com"])
db.set_profile(client2_ip, "normal", custom_allowlist=["reddit.com"])

# Helper function to send DNS query
def send_query(domain, client_ip):
    print(f"Sending query for {domain} from {client_ip}")
    request = DNSRecord.question(domain, qtype='A')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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

# Run tests
print("\n=== Testing Phase 3 End-to-End ===")

# Test client1 (should block reddit.com)
client1_result = send_query(test_domain, client1_ip)

# Test client2 (should allow reddit.com)
client2_result = send_query(test_domain, client2_ip)

# Test normal domain (should resolve for both)
client1_normal = send_query(normal_domain, client1_ip)
client2_normal = send_query(normal_domain, client2_ip)

# Verify results
print("\n=== Verification ===")
assert client1_result == 3, f"Expected NXDOMAIN (3) for client1, got {client1_result}"
assert client2_result == 0, f"Expected NOERROR (0) for client2, got {client2_result}"
assert client1_normal == 0, f"Expected NOERROR (0) for normal domain, got {client1_normal}"
assert client2_normal == 0, f"Expected NOERROR (0) for normal domain, got {client2_normal}"

# Check query log
def check_query_log():
    print("\nChecking query log...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Check for client1's blocked query
    cursor.execute("""
        SELECT * FROM query_log
        WHERE client_ip = ? AND domain = ? AND blocked = 1
        ORDER BY timestamp DESC LIMIT 1
    """, (client1_ip, test_domain))
    client1_log = cursor.fetchone()
    assert client1_log is not None, f"No blocked query log found for client1"
    print(f"Found blocked query log for client1: {client1_log}")

    # Check for client2's allowed query
    cursor.execute("""
        SELECT * FROM query_log
        WHERE client_ip = ? AND domain = ? AND blocked = 0
        ORDER BY timestamp DESC LIMIT 1
    """, (client2_ip, test_domain))
    client2_log = cursor.fetchone()
    assert client2_log is not None, f"No allowed query log found for client2"
    print(f"Found allowed query log for client2: {client2_log}")

    # Check for normal domain queries
    cursor.execute("""
        SELECT * FROM query_log
        WHERE domain = ? AND blocked = 0
        ORDER BY timestamp DESC LIMIT 2
    """, (normal_domain,))
    normal_logs = cursor.fetchall()
    assert len(normal_logs) == 2, f"Expected 2 normal domain logs, got {len(normal_logs)}"
    print(f"Found {len(normal_logs)} normal domain logs")

    conn.close()

check_query_log()

print("\n=== All Phase 3 tests passed successfully ===")