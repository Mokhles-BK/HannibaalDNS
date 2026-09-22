import os
import threading
import time

from database import Database
from anomaly_detection import AnomalyDetector
from blocklist_manager import BlocklistManager
import config


class FilteringEngine:
    """
    Per-transport instance: UDP, DoT, and DoH each build their own
    FilteringEngine, but all share one sqlite DB (config.DB_PATH) and one
    on-disk blocklist cache directory, so state is consistent across
    restarts even though the processes don't talk to each other directly.

    The blocklist registry starts EMPTY. Nothing is blocked until a list
    is registered (via the dashboard's /api/blocklists, or directly through
    self.blocklist_manager.add_list(...)). This replaces the old
    single-URL StevenBlack-only default.

    See blocklist_manager.BlocklistManager for why sync_registry() exists
    and is called from the refresh loop below: a list added through the
    dashboard (which only the DoH process's engine can do) needs a way to
    reach the UDP and DoT processes' engines too.
    """

    REFRESH_INTERVAL_SECONDS = 6 * 3600

    def __init__(self, db_path=None, blocklist_url=None):
        # blocklist_url is accepted only for backward compatibility with
        # any existing call site that still passes it; it is IGNORED. The
        # single-URL default is gone -- use the registry (add_list) instead.
        if blocklist_url is not None:
            print("[FilteringEngine] blocklist_url is no longer used; "
                  "register lists via BlocklistManager.add_list() instead.")

        db_path = config.DB_PATH if db_path is None else db_path
        self.allowlist = set(["localhost"])
        self.anomaly_detector = AnomalyDetector(db_path)
        self.db = Database(db_path, query_callback=self.anomaly_detector.record_query)
        self.blocklist_manager = BlocklistManager(db_path)

        self._last_scheduled_refresh = time.time()
        self._refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self._refresh_thread.start()

    def check(self, domain, client_ip=None):
        """
        Returns (blocked: bool, blocked_by: str|None).

        Precedence (CLAUDE.md): per-client allow > per-client deny >
        blocklists (registry). Custom per-client lists use exact-domain
        matching, same as before this change -- they do NOT walk
        subdomains the way the registry's blocklists do. That's a
        pre-existing behavior, not something introduced here; flagging it
        rather than changing it, since it's outside what was asked.
        """
        domain = domain.lower().rstrip(".")

        if client_ip:
            profile = self.db.get_profile(client_ip)
            if domain in profile["custom_allowlist"]:
                return False, None
            if domain in profile["custom_blocklist"]:
                return True, "custom_denylist"

        if domain in self.allowlist:
            return False, None

        return self.blocklist_manager.match(domain)

    def is_blocked(self, domain, client_ip=None):
        """Back-compat shim for any caller still using the old boolean-only
        API. Prefer check(), which also reports which list blocked it."""
        blocked, _ = self.check(domain, client_ip)
        return blocked

    def force_reload(self):
        """Back-compat name: refresh every registered list right now."""
        self.blocklist_manager.refresh_all()

    def _refresh_loop(self):
        while True:
            time.sleep(60)

            # Pick up lists added/removed/toggled by ANOTHER process (e.g.
            # the dashboard) before deciding whether a content refresh is
            # due. Without this, a brand-new list registered after this
            # process started would never be seen here, even after a
            # restart-free refresh -- refresh_all() only knows about IDs
            # already loaded into memory at __init__ time.
            self.blocklist_manager.sync_registry()

            if os.path.exists("reload.trigger"):
                print("[FilteringEngine] Reload trigger detected")
                self.blocklist_manager.refresh_all()
                try:
                    os.remove("reload.trigger")
                except OSError:
                    pass
                self._last_scheduled_refresh = time.time()

            if time.time() - self._last_scheduled_refresh >= self.REFRESH_INTERVAL_SECONDS:
                print("[FilteringEngine] Scheduled blocklist refresh")
                self.blocklist_manager.refresh_all()
                self._last_scheduled_refresh = time.time()
