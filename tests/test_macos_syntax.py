"""Non-activating native parser checks. Never opens/enables live PF rules."""
from pathlib import Path
import subprocess
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from policy import compile_policy, compile_quarantine
from pf_driver import ANCHOR


@unittest.skipUnless(sys.platform == "darwin" and Path("/sbin/pfctl").exists(), "macOS parser required")
class NativeSyntaxTests(unittest.TestCase):
    def parse(self, text):
        result = subprocess.run(["/sbin/pfctl", "-n", "-v", "-f", "-"], input=text,
                                text=True, capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_gate_canonical_order_is_observed_not_assumed(self):
        canonical = self.parse(f'anchor "{ANCHOR}" quick\n')
        self.assertIn(f'anchor "{ANCHOR}" quick all', canonical)

    def test_active_and_quarantine_rules_parse(self):
        config = {"physical": ["en0"], "tunnel": "utun3", "endpoints": [
            {"address": "1.1.1.1", "port": 443, "protocol": "tcp"},
            {"address": "2606:4700:4700::1111", "port": 8443, "protocol": "udp"}],
            "gateways": [{"interface": "en0", "address": "192.168.1.1", "subnet": "192.168.1.0/24"}]}
        for rules in (compile_policy(config), compile_quarantine(config), compile_quarantine({})):
            with self.subTest(rules=rules):
                self.assertIn('label "v2box_default_deny"', self.parse(rules))


if __name__ == "__main__": unittest.main()
