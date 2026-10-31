import copy
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from controller import Controller, StateStore
from coordinator import Coordinator
from pf_driver import PFDriver
from policy import compile_quarantine
from test_pf_driver import Kernel, Tokens, CONFIG


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.kernel = Kernel()
        self.controller = Controller(StateStore(self.temp.name), PFDriver(self.kernel.run, Tokens()))
        self.coordinator = Coordinator(self.controller)
        self.base = {"physical": ["en0"], "tunnel": "utun3",
                     "gateways": [{"interface": "en0", "address": "192.168.1.1", "subnet": "192.168.1.0/24"}]}
        self.inventory = {"version": 1, "profiles": {"primary": {
            "revision": "1", "expires_at": 2000, "endpoints": copy.deepcopy(CONFIG["endpoints"])}}}

    def enable(self):
        self.controller.enable(CONFIG)

    def test_unknown_profile_revokes_stale_tunnel_and_endpoint(self):
        self.enable()
        self.coordinator.update(self.base, self.inventory, "primary", 1000)
        self.assertIn("on utun3", self.kernel.rules)
        result = self.coordinator.update(self.base, self.inventory, "unknown", 1000)
        self.assertNotIn("utun3", self.kernel.rules)
        self.assertNotIn("1.1.1.1", self.kernel.rules)
        self.assertIn("to 192.168.1.1 icmp-type echoreq no state", self.kernel.rules)
        self.assertEqual(result["policy_mode"], "quarantine")
        self.assertTrue(self.kernel.enabled)

    def test_expiry_enters_quarantine(self):
        self.enable()
        result = self.coordinator.update(self.base, self.inventory, "primary", 2000)
        self.assertEqual(result["policy_mode"], "quarantine")

    def test_approved_revision_leaves_quarantine(self):
        self.enable()
        self.coordinator.update(self.base, self.inventory, "unknown", 1000)
        self.inventory["profiles"]["primary"]["endpoints"][0]["address"] = "8.8.8.8"
        self.inventory["profiles"]["primary"]["revision"] = "2"
        result = self.coordinator.update(self.base, self.inventory, "primary", 1001)
        self.assertEqual(result["policy_mode"], "approved")
        self.assertIn("to 8.8.8.8", self.kernel.rules)
        self.assertNotIn("1.1.1.1", self.kernel.rules)

    def test_unknown_profile_never_reenables_after_disable(self):
        self.enable()
        self.controller.disable()
        self.kernel.calls.clear()
        result = self.coordinator.update(self.base, self.inventory, "unknown", 1000)
        self.assertEqual(result["state"], "off")
        self.assertEqual(self.kernel.rules, "")
        for args, _ in self.kernel.calls:
            self.assertNotIn("-f", args)
            self.assertNotIn("-E", args)

    def test_invalid_gateway_falls_back_to_deny_only(self):
        self.enable()
        self.base["gateways"][0]["address"] = "8.8.8.8"
        self.coordinator.update(self.base, self.inventory, "primary", 1000)
        self.assertNotIn("192.168", self.kernel.rules)
        self.assertNotIn("to 8.8.8.8", self.kernel.rules)
        self.assertNotIn("utun", self.kernel.rules)
        self.assertIn("block drop out quick all", self.kernel.rules)

    def test_quarantine_drops_broad_lan_passes(self):
        self.base["lan"] = ["192.168.0.0/16"]
        rules = compile_quarantine(self.base)
        self.assertNotIn("to 192.168.0.0/16", rules)
        self.assertIn("to 192.168.1.1", rules)

    def test_no_hardware_inventory_quarantine_still_blocks(self):
        rules = compile_quarantine({})
        self.assertNotIn("en0", rules)
        self.assertIn("v2box_default_deny", rules)


if __name__ == "__main__": unittest.main()
