import os
import tempfile
import threading
import unittest
from http.server import HTTPServer, SimpleHTTPRequestHandler

from filtering import FilteringEngine


class TestHannibaalDNS(unittest.TestCase):
    """
    Rewritten for step 5a's multi-blocklist registry (blocked_domains no
    longer exists; the registry starts EMPTY until a list is registered).
    Each test gets its own throwaway sqlite db (never the real
    hannibaaldns.db -- the old version of this file silently read
    whatever was already in the production DB, which is why two of its
    tests could pass or fail depending on unrelated manual testing done
    earlier the same day). A local HTTP server serves a tiny synthetic
    list so these tests don't depend on network access or StevenBlack's
    current live content.
    """

    @classmethod
    def setUpClass(cls):
        cls._list_dir = tempfile.mkdtemp()
        with open(os.path.join(cls._list_dir, "blocked.txt"), "w") as f:
            f.write("doubleclick.net\nads.example.com\n")
        cls._server = HTTPServer(
            ("127.0.0.1", 0),
            lambda *a: SimpleHTTPRequestHandler(*a, directory=cls._list_dir),
        )
        cls._server_port = cls._server.server_address[1]
        cls._thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._thread.start()

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()

    def setUp(self):
        self.db_path = tempfile.mktemp(suffix=".db")
        self.engine = FilteringEngine(db_path=self.db_path)
        self.db = self.engine.db

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _list_url(self):
        return f"http://127.0.0.1:{self._server_port}/blocked.txt"

    def test_registry_starts_empty(self):
        # Step 5a design: nothing is blocked until a list is registered.
        self.assertEqual(self.engine.blocklist_manager.list_lists(), [])
        self.assertFalse(self.engine.is_blocked("doubleclick.net"))

    def test_blocklist_loading(self):
        list_id = self.engine.blocklist_manager.add_list(
            "Test list", self._list_url(), "domains"
        )
        self.assertGreater(
            self.engine.blocklist_manager._get_row(list_id)["entry_count"], 0
        )
        self.assertTrue(self.engine.is_blocked("doubleclick.net"))

    def test_allowlist_override(self):
        # localhost is always allowed via FilteringEngine.allowlist, even
        # with a list registered -- this is a static allowlist, not the
        # per-list registry, so there's nothing to add localhost to; just
        # confirm the precedence holds with a list active.
        self.engine.blocklist_manager.add_list(
            "Test list", self._list_url(), "domains"
        )
        self.assertIn("localhost", self.engine.allowlist)
        self.assertFalse(self.engine.is_blocked("localhost"))

    def test_client_profile_custom_block(self):
        client_ip = "192.168.1.50"
        self.db.set_profile(client_ip, "strict", custom_blocklist=["custom-bad.com"])
        self.assertTrue(self.engine.is_blocked("custom-bad.com", client_ip))
        self.assertFalse(self.engine.is_blocked("custom-bad.com"))  # not globally blocked

    def test_client_profile_custom_allow(self):
        client_ip = "192.168.1.50"
        self.engine.blocklist_manager.add_list(
            "Test list", self._list_url(), "domains"
        )
        self.assertTrue(self.engine.is_blocked("doubleclick.net"))
        self.db.set_profile(client_ip, "custom", custom_allowlist=["doubleclick.net"])
        self.assertFalse(self.engine.is_blocked("doubleclick.net", client_ip))


if __name__ == '__main__':
    unittest.main()
