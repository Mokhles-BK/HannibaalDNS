import time
import threading
import math
import sqlite3
import queue
from collections import defaultdict, deque

class AnomalyDetector:
    def __init__(self, db_path="hannibaaldns.db", window_size=60):
        self.db_path = db_path
        self.window_size = window_size  # seconds
        self.lock = threading.Lock()
        self.query_history = defaultdict(deque)
        self.client_ip_map = {}  # domain -> client_ip tracking
        self.entropy_cache = {}
        self.anomaly_queue = queue.Queue(maxsize=1000)
        self.anomaly_thresholds = {
            "subdomain_length": 50,
            "query_frequency": 5,  # queries per second
            "entropy_threshold": 4.05,
            "txt_record_pattern": 0.7  # probability threshold
        }
        self.last_anomaly_logged = {}  # Track last logged anomaly for each domain
        self.anomaly_cooldown = 300  # 5 minutes cooldown in seconds

        # Start background anomaly writer thread
        self.anomaly_writer_thread = threading.Thread(target=self._anomaly_writer_loop, daemon=True)
        self.anomaly_writer_thread.start()

        # Start background anomaly detection thread
        self.detection_thread = threading.Thread(target=self._anomaly_detection_loop, daemon=True)
        self.detection_thread.start()

    def _calculate_entropy(self, domain):
        if domain in self.entropy_cache:
            return self.entropy_cache[domain]

        # Calculate Shannon entropy of the subdomain (excluding dots and TLD)
        subdomain = domain.split('.')[0] if domain.count('.') > 0 else domain
        chars = set(subdomain)
        if not chars:
            return 0

        entropy = 0
        for char in chars:
            p = subdomain.count(char) / len(subdomain)
            entropy -= p * math.log2(p)

        self.entropy_cache[domain] = entropy
        return entropy

    def _check_subdomain_length(self, domain):
        parts = domain.split('.')
        if len(parts) >= 2:
            subdomain = parts[-2]
            return len(subdomain) > self.anomaly_thresholds["subdomain_length"]
        return False

    def _check_query_frequency(self, domain):
        current_time = time.time()
        with self.lock:
            domain_queries = list(self.query_history[domain])
        recent_queries = [t for t in domain_queries if current_time - t < self.window_size]
        frequency = len(recent_queries) / self.window_size
        return frequency > self.anomaly_thresholds["query_frequency"]

    def _check_entropy(self, domain):
        entropy = self._calculate_entropy(domain)
        return entropy > self.anomaly_thresholds["entropy_threshold"]

    def _check_txt_record_pattern(self, domain):
        return False

    def _calculate_anomaly_score(self, domain, client_ip):
        score = 0
        if self._check_subdomain_length(domain):
            score += 0.3
        if self._check_query_frequency(domain):
            score += 0.3
        if self._check_entropy(domain):
            score += 0.2
        return score

    def _anomaly_writer_loop(self):
        while True:
            try:
                item = self.anomaly_queue.get()
                if item is None:
                    break
                domain, client_ip, score, reasons_str = item
                with self.lock:
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO anomaly_log
                        (domain, client_ip, score, reasons)
                        VALUES (?, ?, ?, ?)
                    ''', (domain, client_ip, score, reasons_str))
                    conn.commit()
                    conn.close()
                self.anomaly_queue.task_done()
            except Exception as e:
                print(f"[Error] Failed to write anomaly log to DB: {e}")

    def _anomaly_detection_loop(self):
        while True:
            time.sleep(1)
            current_time = time.time()

            with self.lock:
                items = list(self.query_history.items())

            for domain, timestamps in items:
                # Get associated client IP if available
                client_ip = self.client_ip_map.get(domain, "unknown")
                score = self._calculate_anomaly_score(domain, client_ip)
                if score > 0:
                    reasons = []
                    if self._check_subdomain_length(domain):
                        reasons.append(f"long_subdomain(length={len(domain.split('.')[-2])})")
                    if self._check_query_frequency(domain):
                        recent_queries = [t for t in timestamps if current_time - t < self.window_size]
                        reasons.append(f"high_frequency({len(recent_queries)}/{self.window_size}s)")
                    if self._check_entropy(domain):
                        reasons.append(f"high_entropy({self._calculate_entropy(domain):.2f})")

                    reasons_str = ', '.join(reasons)

                    # Check if we should log this anomaly (cooldown check)
                    key = (domain, reasons_str)
                    if key not in self.last_anomaly_logged or current_time - self.last_anomaly_logged[key] > self.anomaly_cooldown:
                        print(f"[ANOMALY] Domain: {domain}, Client: {client_ip}, Score: {score:.2f}, Reasons: {reasons_str}")

                        try:
                            self.anomaly_queue.put_nowait((domain, client_ip, score, reasons_str))
                            self.last_anomaly_logged[key] = current_time
                        except queue.Full:
                            print("[Warning] Anomaly log queue is full. Dropping entry.")

    def record_query(self, client_ip, domain, query_type, blocked, response_time):
        current_time = time.time()

        with self.lock:
            self.query_history[domain].append(current_time)
            self.client_ip_map[domain] = client_ip

            while self.query_history[domain] and current_time - self.query_history[domain][0] > self.window_size:
                self.query_history[domain].popleft()