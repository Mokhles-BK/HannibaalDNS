import unittest
from filtering import FilteringEngine
from database import Database

class TestHannibaalDNS(unittest.TestCase):
    def setUp(self):
        self.db = Database("test_hannibaaldns.db")
        self.engine = FilteringEngine()
        self.engine.db = self.db

    def test_blocklist_loading(self):
        self.assertGreater(len(self.engine.blocked_domains), 0)

    def test_allowlist_override(self):
        # localhost should be allowed even if someone put it in blocked
        self.engine.blocked_domains.add("localhost")
        self.assertFalse(self.engine.is_blocked("localhost"))

    def test_client_profile_custom_block(self):
        client_ip = "192.168.1.50"
        self.db.set_profile(client_ip, "strict", custom_blocklist=["custom-bad.com"])
        self.assertTrue(self.engine.is_blocked("custom-bad.com", client_ip))
        self.assertFalse(self.engine.is_blocked("custom-bad.com"))  # not globally blocked

    def test_client_profile_custom_allow(self):
        client_ip = "192.168.1.50"
        # doubleclick.net is blocked globally by StevenBlack hosts
        self.assertTrue(self.engine.is_blocked("doubleclick.net"))
        # Allow it for this client profile
        self.db.set_profile(client_ip, "custom", custom_allowlist=["doubleclick.net"])
        self.assertFalse(self.engine.is_blocked("doubleclick.net", client_ip))

if __name__ == '__main__':
    unittest.main()
