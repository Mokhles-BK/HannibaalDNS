import os
import threading
import time
import urllib.request
from database import Database
from anomaly_detection import AnomalyDetector
import config

class FilteringEngine:
    def __init__(self, blocklist_url=config.BLOCKLIST_URL, db_path=config.DB_PATH):
        self.blocklist_url = blocklist_url
        self.blocked_domains = set()
        self.allowlist = set(["localhost"])
        self.lock = threading.Lock()
        self.last_refresh_time = time.time()
        self.anomaly_detector = AnomalyDetector(db_path)
        self.db = Database(db_path, query_callback=self.anomaly_detector.record_query)
        self.load_blocklist()

        # Start background refresh thread
        self.refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self.refresh_thread.start()

    def load_blocklist(self):
        print("Loading blocklist...")
        start_time = time.time()
        try:
            with urllib.request.urlopen(self.blocklist_url) as response:
                content = response.read().decode('utf-8')
                new_domains = set()
                for line in content.splitlines():
                    if line.startswith("#") or not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        domain = parts[1].lower()
                        new_domains.add(domain)

                with self.lock:
                    self.blocked_domains = new_domains

                duration = time.time() - start_time
                print(f"Loaded {len(self.blocked_domains)} domains in {duration:.2f}s")
        except Exception as e:
            print(f"Failed to load blocklist: {e}")

    def _refresh_loop(self):
        while True:
            # Check for reload trigger every minute
            time.sleep(60)
            if os.path.exists("reload.trigger"):
                print("Reload trigger detected")
                self.load_blocklist()
                os.remove("reload.trigger")
                self.last_refresh_time = time.time()

            # Check if 6 hours have elapsed since last refresh
            if time.time() - self.last_refresh_time >= 6 * 3600:
                print("Scheduled refresh time reached")
                self.load_blocklist()
                self.last_refresh_time = time.time()

    def is_blocked(self, domain, client_ip=None):
        domain = domain.lower().rstrip('.')

        # Check client-specific profile if IP provided
        if client_ip:
            profile = self.db.get_profile(client_ip)
            if domain in profile['custom_allowlist']:
                return False
            if domain in profile['custom_blocklist']:
                return True

        # Check global allowlist
        if domain in self.allowlist:
            return False

        with self.lock:
            # Check for exact or wildcard subdomain blocking
            return domain in self.blocked_domains or any(domain.endswith("." + b) for b in self.blocked_domains)

    def force_reload(self):
        self.load_blocklist()
