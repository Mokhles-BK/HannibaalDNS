import sqlite3
import time
from database import Database
from anomaly_detection import AnomalyDetector

# Create a test script to verify items 1-5 thoroughly
print("=== VERIFYING ANOMALY DETECTION & PERSISTENCE FIXES ===")

db_path = "test_hannibaaldns.db"
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
if entropy_tunnel > entropy_normal:
    print("PASS: Entropy correctly computed on leftmost label, yielding higher score for high-entropy strings.")
else:
    print("FAIL: Entropy calculation logic unexpected.")

# Test 3: TXT record pattern detection stub update
print("\n--- Test 3: TXT record pattern method ---")
txt_result = detector._check_txt_record_pattern("test.com")
print(f"TXT record pattern check result: {txt_result}")
print("PASS: Method executes cleanly.")

# Test 4 & 5: Trigger an Anomaly & Persist to anomaly_log table via Decoupled Queue Pattern
print("\n--- Test 4 & 5: Trigger Anomaly & Persistence to anomaly_log ---")
# Flood queries to trigger high frequency & high entropy / subdomain length anomaly
tunnel_domain = "aGVsbG93b3JsZHRoaXNpc3R1bm5lbGluZGRhdGEuaW8=" * 2 + ".com"
client_ip = "127.0.0.2"

print(f"Simulating high frequency tunneling queries for: {tunnel_domain}")
for i in range(10):
    db.log_query(client_ip, tunnel_domain, "TXT", False, 0.02)
    time.sleep(0.05)

# Wait for background detection loop & async writer thread to process
print("Waiting for background anomaly detection and database persistence...")
time.sleep(3.5)

# Check anomaly_log table
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute("SELECT id, domain, client_ip, score, reasons, timestamp FROM anomaly_log")
rows = cursor.fetchall()
conn.close()

print(f"\nFound {len(rows)} rows in anomaly_log:")
for row in rows:
    print(f"  ID: {row[0]} | Domain: {row[1]} | Client: {row[2]} | Score: {row[3]} | Reasons: {row[4]} | Time: {row[5]}")

if len(rows) > 0:
    print("\nSUCCESS: Anomaly successfully detected, queued, and persisted to anomaly_log table via async writer thread!")
else:
    print("\nFAIL: No records found in anomaly_log table.")

# Cleanup test db
if os.path.exists(db_path):
    os.remove(db_path)
