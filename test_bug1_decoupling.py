import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path


PROJECT_ROOT = Path(
    os.environ.get("HANNIBAALDNS_TEST_ROOT", Path(__file__).resolve().parent)
).resolve()


class Phase4RegressionTests(unittest.TestCase):
    def test_database_is_independent_from_anomaly_detection(self):
        script = r"""
import os
import sqlite3
import sys
import threading
import time

sys.path.insert(0, os.environ["HANNIBAALDNS_TEST_ROOT"])

from database import Database

db_path = os.environ["HANNIBAALDNS_TEST_DB"]
db = Database(db_path)
thread_names = [thread.name for thread in threading.enumerate()]
anomaly_module_loaded = "anomaly_detection" in sys.modules
anomaly_threads_running = any("anomaly" in name.lower() for name in thread_names)

db.log_query("192.0.2.10", "example.com", "A", False, 0.01)
db.log_queue.join()
db.log_queue.put(None)
db.writer_thread.join(timeout=2)

conn = sqlite3.connect(db_path)
query_count = conn.execute("SELECT COUNT(*) FROM query_log").fetchone()[0]
conn.close()

print(f"anomaly_detection module loaded: {anomaly_module_loaded}")
print(f"anomaly detector threads running: {anomaly_threads_running}")
print(f"active threads: {thread_names}")
print(f"query_log rows: {query_count}")

for suffix in ("", "-shm", "-wal"):
    path = db_path + suffix
    if os.path.exists(path):
        os.remove(path)

assert not anomaly_module_loaded, "Database imported anomaly_detection"
assert not anomaly_threads_running, "Database started anomaly detector threads"
assert query_count == 1, f"expected one query_log row, got {query_count}"
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            env = os.environ.copy()
            env["HANNIBAALDNS_TEST_ROOT"] = str(PROJECT_ROOT)
            env["HANNIBAALDNS_TEST_DB"] = os.path.join(temp_dir, "database-only.db")
            result = subprocess.run(
                [sys.executable, "-c", script],
                cwd=PROJECT_ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=10,
            )

        print(result.stdout, end="")
        self.assertEqual(
            result.returncode,
            0,
            f"decoupling regression failed:\n{result.stdout}\n{result.stderr}",
        )

    def test_localhost_frequency_anomaly_is_cooldown_deduplicated(self):
        sys.path.insert(0, str(PROJECT_ROOT))

        from anomaly_detection import AnomalyDetector
        from database import Database

        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = os.path.join(temp_dir, "anomaly-dedup.db")
            detector = AnomalyDetector(db_path, window_size=5)
            db = Database(db_path, query_callback=detector.record_query)

            self.assertFalse(detector._check_subdomain_length("localhost"))
            self.assertFalse(detector._check_entropy("localhost"))

            for _ in range(40):
                db.log_query("127.0.0.1", "localhost", "A", False, 0.001)

            self.assertTrue(detector._check_query_frequency("localhost"))
            time.sleep(6)

            conn = sqlite3.connect(db_path)
            row_count = conn.execute(
                "SELECT COUNT(*) FROM anomaly_log WHERE domain = ?",
                ("localhost",),
            ).fetchone()[0]
            rows = conn.execute(
                "SELECT client_ip, score, reasons, timestamp "
                "FROM anomaly_log WHERE domain = ? ORDER BY id",
                ("localhost",),
            ).fetchall()
            conn.close()

            db.log_queue.put(None)
            db.writer_thread.join(timeout=2)

            print(f"anomaly_log rows for localhost over 6 seconds: {row_count}")
            for row in rows:
                print(f"  {row}")

            self.assertEqual(
                row_count,
                1,
                "the stable anomaly identity must produce one row during sustained traffic",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
