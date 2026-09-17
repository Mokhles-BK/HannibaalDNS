import sqlite3
import time
from database import Database

# Create a test script to verify all fixes
print("=== FINAL VERIFICATION OF ALL FIXES ===")

db_path = "test_hannibaaldns_final.db"
import os
if os.path.exists(db_path):
    os.remove(db_path)

db = Database(db_path)

# Test 1: Crash Bug Fix (single-label domain)
print("\n--- Test 1: Single-label domain crash fix ---")
try:
    db.log_query("127.0.0.1", "localhost", "A", False, 0.01)
    time.sleep(1.5)
    print("PASS: 'localhost' logged successfully without IndexError crash.")
except Exception as e:
    print(f"FAIL: Crashed on 'localhost': {e}")

# Test 2: Entropy Calculation Fix (isolated to subdomain label)
print("\n--- Test 2: Entropy calculation isolation ---")
detector = db.anomaly_detector
entropy_normal = detector._calculate_entropy("example.com")
entropy_tunnel = detector._calculate_entropy("aGVsbG93b3JsZHRoaXNpc3R1bm5lbGluZGRhdGEuaW8=")
print(f"Entropy for 'example.com' (leftmost label): {entropy_normal:.2f}")
print(f"Entropy for high-entropy tunneling label: {entropy_tunnel:.2f}")

# Test localhost specifically
localhost_entropy = detector._calculate_entropy("localhost")
print(f"Entropy for 'localhost': {localhost_entropy:.2f}")
if localhost_entropy < 4.05:
    print("PASS: localhost entropy is below new threshold")
else:
    print("FAIL: localhost entropy is above threshold")

# Test 3: TXT record pattern method
print("\n--- Test 3: TXT record pattern method ---")
txt_result = detector._check_txt_record_pattern("test.com")
print(f"TXT record pattern check result: {txt_result}")
print("PASS: Method executes cleanly.")

# Test 4 & 5: Trigger Anomaly & Persistence to anomaly_log with deduplication
print("\n--- Test 4 & 5: Trigger Anomaly & Persistence with deduplication ---")

# Flood queries to trigger high frequency & high entropy / subdomain length anomaly
tunnel_domain = "aGVsbG93b3JsZHRoaXNpc3R1bm5lbGluZGRhdGEuaW8=" * 2 + ".com"
client_ip = "127.0.0.2"

print(f"Simulating high frequency tunneling queries for: {tunnel_domain}")
for i in range(15):
    db.log_query(client_ip, tunnel_domain, "TXT", False, 0.02)
    time.sleep(0.05)

# Wait for background detection loop & async writer thread to process
print("Waiting for background anomaly detection and database persistence...")
time.sleep(4.5)

# Check anomaly_log table
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute("SELECT id, domain, client_ip, score, reasons, timestamp FROM anomaly_log")
rows = cursor.fetchall()
conn.close()

print(f"\nFound {len(rows)} rows in anomaly_log:")
for row in rows:
    print(f"  ID: {row[0]} | Domain: {row[1]} | Client: {row[2]} | Score: {row[3]} | Reasons: {row[4]} | Time: {row[5]}")

# Verify localhost is not in the results
localhost_in_results = any(row[1] == "localhost" for row in rows)
if localhost_in_results:
    print("\nFAIL: localhost still appears in anomaly_log")
else:
    print("\nPASS: localhost does not appear in anomaly_log")

# Verify tunneling domain is in the results
if len(rows) > 0 and rows[0][1] == tunnel_domain:
    print("\nPASS: Tunneling domain correctly logged as anomaly")
else:
    print("\nFAIL: Tunneling domain not logged as anomaly")

# Cleanup test db
if os.path.exists(db_path):
    os.remove(db_path)

print("\n=== ALL TESTS COMPLETED ===")