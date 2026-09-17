import sqlite3
import socket
import time
from dnslib import DNSRecord
from filtering import FilteringEngine
from database import Database

def verify_phase3():
    print("=== Phase 3 End-to-End Verification ===")

    # 1. Initialize DB and set up two different profiles
    db_path = "test_phase3.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    db = Database(db_path)

    ip_strict = "10.0.0.50"
    ip_lenient = "10.0.0.51"

    # Strict profile blocks reddit.com specifically
    db.set_profile(ip_strict, "strict", custom_blocklist=["reddit.com"])
    # Lenient profile allows reddit.com explicitly (or has empty custom lists)
    db.set_profile(ip_lenient, "lenient", custom_allowlist=["reddit.com"])

    print(f"Client {ip_strict} profile: blocks reddit.com")
    print(f"Client {ip_lenient} profile: allows reddit.com")

    # 2. Test is_blocked logic directly with client IPs
    engine = FilteringEngine(db_path=db_path)

    # reddit.com is NOT in the default StevenBlack blocklist, but strict profile blocks it.
    # Let's verify:
    strict_reddit = engine.is_blocked("reddit.com", client_ip=ip_strict)
    lenient_reddit = engine.is_blocked("reddit.com", client_ip=ip_lenient)

    print(f"is_blocked('reddit.com', client_ip={ip_strict}) -> {strict_reddit} (Expected: True)")
    print(f"is_blocked('reddit.com', client_ip={ip_lenient}) -> {lenient_reddit} (Expected: False)")

    assert strict_reddit == True, "Strict client should block reddit.com"
    assert lenient_reddit == False, "Lenient client should allow reddit.com"

    # 3. Test logging queries to DB
    print("\nSimulating query logs...")
    db.log_query(ip_strict, "reddit.com", "A", True, 0.015)
    db.log_query(ip_lenient, "reddit.com", "A", False, 0.025)
    db.log_query(ip_strict, "google.com", "A", False, 0.010)

    # 4. Query the query_log table directly and print rows
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT client_ip, domain, query_type, blocked, response_time, timestamp FROM query_log")
    rows = cursor.fetchall()
    conn.close()

    print("\n--- QUERY LOG TABLE CONTENTS ---")
    print(f"{'CLIENT IP':<15} | {'DOMAIN':<15} | {'TYPE':<6} | {'BLOCKED':<8} | {'TIME (s)':<10} | {'TIMESTAMP'}")
    print("-" * 75)
    for row in rows:
        print(f"{row[0]:<15} | {row[1]:<15} | {row[2]:<6} | {str(row[3]):<8} | {row[4]:<10} | {row[5]}")

    assert len(rows) == 3, f"Expected 3 logged queries, found {len(rows)}"
    print("\n=== Phase 3 End-to-End Verification PASSED Successfully ===")

if __name__ == '__main__':
    import os
    verify_phase3()
