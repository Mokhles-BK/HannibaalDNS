import sqlite3
import time
from database import Database

# Create a test script to verify anomaly deduplication
print("=== VERIFYING ANOMALY DEDUPLICATION ===")

db_path = "test_hannibaaldns_dedup.db"
import os
if os.path.exists(db_path):
    os.remove(db_path)

db = Database(db_path)

# Test localhost specifically to ensure it no longer triggers false positives
print("\n--- Testing localhost (should NOT trigger anomaly) ---")
for i in range(5):
    db.log_query("127.0.0.1", "localhost", "A", False, 0.01)
    time.sleep(0.1)

# Wait for background detection loop to process
print("Waiting for background anomaly detection...")
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

# Test tunneling-style domain to ensure it still triggers anomalies
print("\n--- Testing tunneling-style domain (should trigger anomaly) ---")
tunnel_domain = "aGVsbG93b3JsZHRoaXNpc3R1bm5lbGluZGRhdGEuaW8=" * 2 + ".com"
client_ip = "127.0.0.2"

print(f"Simulating high frequency tunneling queries for: {tunnel_domain}")
for i in range(10):
    db.log_query(client_ip, tunnel_domain, "TXT", False, 0.02)
    time.sleep(0.05)

# Wait for background detection loop to process
print("Waiting for background anomaly detection...")
time.sleep(3.5)

# Check anomaly_log table again
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute("SELECT id, domain, client_ip, score, reasons, timestamp FROM anomaly_log")
rows = cursor.fetchall()
conn.close()

print(f"\nFound {len(rows)} rows in anomaly_log:")
for row in rows:
    print(f"  ID: {row[0]} | Domain: {row[1]} | Client: {row[2]} | Score: {row[3]} | Reasons: {row[4]} | Time: {row[5]}")

# Check if localhost is in the results
localhost_in_results = any(row[1] == "localhost" for row in rows)
if localhost_in_results:
    print("\nFAIL: localhost still appears in anomaly_log")
else:
    print("\nPASS: localhost does not appear in anomaly_log")

# Cleanup test db
if os.path.exists(db_path):
    os.remove(db_path)