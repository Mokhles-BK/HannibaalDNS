import sqlite3
import threading
import queue
from datetime import datetime
import config

class Database:
    def __init__(self, db_path=None, query_callback=None):
        self.db_path = config.DB_PATH if db_path is None else db_path
        self.lock = threading.Lock()
        self.log_queue = queue.Queue(maxsize=1000)
        self.query_callback = query_callback
        self.init_db()

        # Start background writer thread for non-blocking logging
        self.writer_thread = threading.Thread(target=self._log_writer_loop, daemon=True)
        self.writer_thread.start()

        # Start background retention-purge thread (step 6). Event, not a
        # plain sleep, so a future clean-shutdown path can wake and stop it
        # early instead of waiting up to 24h.
        self._retention_stop = threading.Event()
        self.retention_thread = threading.Thread(target=self._retention_loop, daemon=True)
        self.retention_thread.start()

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
            # Safe migration: add blocked_by if this DB predates step 5a.
            cursor.execute("PRAGMA table_info(query_log)")
            existing_cols = {row[1] for row in cursor.fetchall()}
            if 'blocked_by' not in existing_cols:
                cursor.execute('ALTER TABLE query_log ADD COLUMN blocked_by TEXT')
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

    def log_query(self, client_ip, domain, query_type, blocked, response_time, blocked_by=None):
        if self.query_callback is not None:
            self.query_callback(client_ip, domain, query_type, blocked, response_time)

        try:
            self.log_queue.put_nowait((client_ip, domain, query_type, blocked, response_time, blocked_by))
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
                client_ip, domain, query_type, blocked, response_time, blocked_by = item
                with self.lock:
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO query_log
                        (client_ip, domain, query_type, blocked, response_time, blocked_by)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (client_ip, domain, query_type, blocked, response_time, blocked_by))
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

    # -----------------------------------------------------------------
    # Log controls (step 6): retention purge, clear-all. CSV export reads
    # directly via phase5/backend/app.py's get_db(), no method needed here.
    # -----------------------------------------------------------------

    def purge_older_than(self, days):
        """
        Delete query_log and anomaly_log rows older than `days` days.
        Returns (queries_deleted, anomalies_deleted). Takes self.lock like
        every other write path here, so this is safe to call concurrently
        with the background writer thread.

        Note: SQLite's datetime('now') has second-level granularity, so
        purge_older_than(0) called within the same second a row was
        written can leave that row behind (timestamp == now, not <).
        Irrelevant at real retention windows (days >= 1); only matters if
        something calls this with days=0 as a "delete everything" shortcut
        -- use clear_all_logs() for that instead.
        """
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM query_log WHERE timestamp < datetime('now', ?)",
                (f'-{int(days)} days',),
            )
            q_deleted = cursor.rowcount
            cursor.execute(
                "DELETE FROM anomaly_log WHERE timestamp < datetime('now', ?)",
                (f'-{int(days)} days',),
            )
            a_deleted = cursor.rowcount
            conn.commit()
            conn.close()
            return q_deleted, a_deleted

    def clear_all_logs(self):
        """Delete every row from query_log and anomaly_log. Destructive,
        no retention window applied -- callers must confirm with the user
        (the dashboard route requires an explicit confirm flag)."""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM query_log")
            q_deleted = cursor.rowcount
            cursor.execute("DELETE FROM anomaly_log")
            a_deleted = cursor.rowcount
            conn.commit()
            conn.close()
            return q_deleted, a_deleted

    def _retention_loop(self):
        """Daemon thread: purge rows older than config.LOG_RETENTION_DAYS
        once at startup and then once every 24h. Runs in addition to (not
        instead of) the manual /api/logs/purge endpoint -- this just means
        a dev instance left running for weeks doesn't grow the DB forever
        even if nobody opens the dashboard."""
        while True:
            try:
                if config.LOG_RETENTION_DAYS > 0:
                    q, a = self.purge_older_than(config.LOG_RETENTION_DAYS)
                    if q or a:
                        print(f"[Retention] purged {q} query_log + {a} anomaly_log "
                              f"rows older than {config.LOG_RETENTION_DAYS} days")
            except Exception as e:
                print(f"[Error] Retention purge failed: {e}")
            self._retention_stop.wait(24 * 60 * 60)
