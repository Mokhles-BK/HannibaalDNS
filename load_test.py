import time
import socket
import concurrent.futures
from dnslib import DNSRecord
from database import Database
from filtering import FilteringEngine
from dns_server import SimpleResolver, DNSServer

def load_test():
    print("=== Concurrency Load Test (50 Concurrent Requests) ===")
    db_path = "loadtest.db"
    import os
    if os.path.exists(db_path):
        os.remove(db_path)

    # Initialize engine & server with WAL enabled DB
    engine = FilteringEngine(db_path=db_path)
    resolver = SimpleResolver('8.8.8.8', engine)
    server = DNSServer(resolver, port=5055)
    server.start_thread()
    time.sleep(1.5)

    try:
        def send_single_query(domain):
            req = DNSRecord.question(domain, qtype='A')
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            t0 = time.time()
            try:
                sock.sendto(req.pack(), ('127.0.0.1', 5055))
                data, _ = sock.recvfrom(512)
                t1 = time.time()
                return (t1 - t0) * 1000 # convert to ms
            except Exception as e:
                print(f"Query error: {e}")
                return None
            finally:
                sock.close()

        # Fire 50 concurrent requests for doubleclick.net (blocked, fast local response)
        num_requests = 50
        print(f"Firing {num_requests} parallel UDP DNS queries...")

        start_overall = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(send_single_query, "doubleclick.net") for _ in range(num_requests)]
            latencies = [f.result() for f in concurrent.futures.as_completed(futures) if f.result() is not None]
        total_overall_time = (time.time() - start_overall) * 1000

        latencies.sort()
        min_lat = latencies[0]
        med_lat = latencies[len(latencies) // 2]
        max_lat = latencies[-1]
        avg_lat = sum(latencies) / len(latencies)

        print(f"\n--- LATENCY METRICS ({len(latencies)} successful responses) ---")
        print(f"Total time for 50 concurrent queries: {total_overall_time:.2f} ms")
        print(f"Min Latency:    {min_lat:.2f} ms")
        print(f"Median Latency: {med_lat:.2f} ms")
        print(f"Max Latency:    {max_lat:.2f} ms")
        print(f"Average Latency:{avg_lat:.2f} ms")

    finally:
        server.stop()

if __name__ == '__main__':
    load_test()
