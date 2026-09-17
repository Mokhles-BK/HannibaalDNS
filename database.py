import sqlite3
import threading
import queue
from datetime import datetime
import anomaly_detection

class Database:
    def __init__(self, db_path="hannibaaldns.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.log_queue = queue.Queue(maxsize=1000)
        self.anomaly_detector = anomaly_detection.AnomalyDetector(db_path)
        self.init_db()

        # Start background writer thread for non-blocking logging
        self.writer_thread = threading.Thread(target=self._log_writer_loop, daemon=True)
        self.writer_thread.start()

    def init_db(self):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            # Client profiles table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS client_profiles (
                    id INTEGER PRIMARY KEY,
                    ip_address TEXT UNIQUE,
                    profile_name TEXT,
                    custom_blocklist TEXT,
                    custom_allowlist TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Query log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS query_log (
                    id INTEGER PRIMARY KEY,
                    client_ip TEXT,
                    domain TEXT,
                    query_type TEXT,
                    blocked BOOLEAN,
                    response_time REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Anomaly log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomaly_log (
                    id INTEGER PRIMARY KEY,
                    domain TEXT,
                    client_ip TEXT,
                    score REAL,
                    reasons TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            conn.close()

    def get_profile(self, ip_address):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT profile_name, custom_blocklist, custom_allowlist
                FROM client_profiles WHERE ip_address = ?
            ''', (ip_address,))
            row = cursor.fetchone()
            conn.close()
            if row:
                return {
                    'profile_name': row[0],
                    'custom_blocklist': set(row[1].split(',')) if row[1] else set(),
                    'custom_allowlist': set(row[2].split(',')) if row[2] else set()
                }
            else:
                # Default profile
                return {
                    'profile_name': 'default',
                    'custom_blocklist': set(),
                    'custom_allowlist': set()
                }

    def set_profile(self, ip_address, profile_name, custom_blocklist=None, custom_allowlist=None):
        # Validate and normalize domains
        if custom_blocklist:
            if any(',' in domain for domain in custom_blocklist):
                raise ValueError("Domains in custom_blocklist cannot contain commas")
            custom_blocklist = [d.lower() for d in custom_blocklist]
        if custom_allowlist:
            if any(',' in domain for domain in custom_allowlist):
                raise ValueError("Domains in custom_allowlist cannot contain commas")
            custom_allowlist = [d.lower() for d in custom_allowlist]

        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO client_profiles
                (ip_address, profile_name, custom_blocklist, custom_allowlist)
                VALUES (?, ?, ?, ?)
            ''', (
                ip_address,
                profile_name,
                ','.join(custom_blocklist) if custom_blocklist else None,
                ','.join(custom_allowlist) if custom_allowlist else None
            ))
            conn.commit()
            conn.close()

    def log_query(self, client_ip, domain, query_type, blocked, response_time):
        # Record query for anomaly detection
        self.anomaly_detector.record_query(client_ip, domain, query_type, blocked, response_time)

        try:
            self.log_queue.put_nowait((client_ip, domain, query_type, blocked, response_time))
        except queue.Full:
            print("[Warning] Log queue is full. Dropping query log entry.")

    def _log_writer_loop(self):
        # This thread is daemon=True, but normal shutdown via KeyboardInterrupt
        # explicitly flushes the queue first via log_queue.put(None) + writer_thread.join()
        while True:
            try:
                item = self.log_queue.get()
                if item is None:
                    break
                client_ip, domain, query_type, blocked, response_time = item
                with self.lock:
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO query_log
                        (client_ip, domain, query_type, blocked, response_time)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (client_ip, domain, query_type, blocked, response_time))
                    conn.commit()
                    conn.close()
                self.log_queue.task_done()
            except Exception as e:
                print(f"[Error] Failed to write query log to DB: {e}")

    def get_stats(self):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT
                    COUNT(*) as total_queries,
                    SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_queries,
                    AVG(response_time) as avg_response_time
                FROM query_log
                WHERE timestamp > datetime('now', '-1 hour')
            ''')
            row = cursor.fetchone()
            conn.close()
            return {
                'total_queries': row[0] if row[0] else 0,
                'blocked_queries': row[1] if row[1] else 0,
                'avg_response_time': row[2] if row[0] and row[2] else 0.0
            }