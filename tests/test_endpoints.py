import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from endpoints import approved_config, EndpointApprovalRequired
from policy import PolicyError, compile_policy


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.base = {"physical": ["en0"], "tunnel": None, "lan": []}
        self.inventory = {"version": 1, "profiles": {
            "first": {"revision": "1", "expires_at": 2000,
                      "endpoints": [{"address": "1.1.1.1", "port": 443, "protocol": "tcp"}]},
            "second": {"revision": "7", "expires_at": 2000,
                       "endpoints": [{"address": "8.8.8.8", "port": 8443, "protocol": "udp"}]}}}

    def test_profile_switch_replaces_not_accumulates(self):
        first = compile_policy(approved_config(self.base, self.inventory, "first", 1000))
        second = compile_policy(approved_config(self.base, self.inventory, "second", 1000))
        self.assertIn("to 1.1.1.1", first)
        self.assertNotIn("1.1.1.1", second)
        self.assertIn("to 8.8.8.8 port 8443", second)

    def test_multiple_preapproved_addresses(self):
        self.inventory["profiles"]["first"]["endpoints"].append({"address": "1.0.0.1", "port": 443, "protocol": "tcp"})
        rules = compile_policy(approved_config(self.base, self.inventory, "first", 1000))
        self.assertIn("to 1.0.0.1", rules)
        self.assertIn("to 1.1.1.1", rules)

    def test_unknown_profile_requires_approval(self):
        with self.assertRaises(EndpointApprovalRequired):
            approved_config(self.base, self.inventory, "unknown", 1000)

    def test_expiry_requires_approval(self):
        with self.assertRaises(EndpointApprovalRequired):
            approved_config(self.base, self.inventory, "first", 2000)

    def test_no_untrusted_hostname_resolution(self):
        self.inventory["profiles"]["first"]["endpoints"][0]["address"] = "vpn.example.invalid"
        with self.assertRaises(PolicyError):
            approved_config(self.base, self.inventory, "first", 1000)

    def test_nan_expiry_rejected(self):
        self.inventory["profiles"]["first"]["expires_at"] = float("nan")
        with self.assertRaises(PolicyError):
            approved_config(self.base, self.inventory, "first", 1000)

    def test_no_mutation(self):
        original = copy.deepcopy(self.inventory)
        config = approved_config(self.base, self.inventory, "first", 1000)
        config["endpoints"].clear()
        self.assertEqual(original, self.inventory)
        self.assertNotIn("endpoints", self.base)


if __name__ == "__main__":
    unittest.main()
