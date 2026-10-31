import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from policy import PolicyError, compile_policy


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.config = {"physical": ["en0"], "tunnel": "utun3",
                       "endpoints": [{"address": "1.1.1.1", "port": 443, "protocol": "tcp"}], "lan": []}

    def test_final_default_deny(self):
        self.assertTrue(compile_policy(self.config).endswith('block drop out quick all label "v2box_default_deny"\n'))

    def test_disconnected_removes_tunnel(self):
        self.config["tunnel"] = None
        rules = compile_policy(self.config)
        self.assertNotIn("utun", rules)
        self.assertIn("to 1.1.1.1 port 443 flags any no state", rules)

    def test_endpoint_change_removes_previous_peer(self):
        self.config["endpoints"][0]["address"] = "8.8.8.8"
        rules = compile_policy(self.config)
        self.assertNotIn("1.1.1.1", rules)
        self.assertNotIn("keep state", rules)

    def test_multiple_profiles_ipv6_udp(self):
        self.config["endpoints"].append({"address": "2606:4700:4700::1111", "port": 8443, "protocol": "udp"})
        self.assertIn("inet6 proto udp to 2606:4700:4700::1111 port 8443 no state", compile_policy(self.config))

    def test_explicit_lan_only(self):
        self.assertNotIn("192.168.1.0/24", compile_policy(self.config))
        self.config["lan"] = ["192.168.1.0/24"]
        self.assertIn("on en0 inet to 192.168.1.0/24 no state", compile_policy(self.config))

    def test_invalid_inputs_rejected(self):
        for field, value in [("physical", ["en0\npass out all"]), ("tunnel", "utun3 all"),
                             ("endpoints", []), ("lan", ["0.0.0.0/0"]),
                             ("lan", ["8.8.8.0/24"]), ("lan", ["192.168.1.1/24"])]:
            with self.subTest(field=field, value=value):
                config = copy.deepcopy(self.config)
                config[field] = value
                with self.assertRaises(PolicyError):
                    compile_policy(config)

    def test_hostname_and_bad_ports_rejected(self):
        for address, port in [("vpn.example.invalid", 443), ("127.0.0.1", 443), ("1.1.1.1", True), ("1.1.1.1", 0)]:
            self.config["endpoints"][0].update(address=address, port=port)
            with self.assertRaises(PolicyError):
                compile_policy(self.config)

    def test_no_unrestricted_dns_or_egress(self):
        rules = compile_policy(self.config)
        self.assertNotIn("egress", rules)
        self.assertNotIn("port 53", rules)

    def test_gateway_changes_replace_old_exception(self):
        self.config["gateways"] = [{"interface": "en0", "address": "192.168.1.1", "subnet": "192.168.1.0/24"}]
        first = compile_policy(self.config)
        self.assertIn("on en0 inet proto icmp to 192.168.1.1 icmp-type echoreq no state", first)
        self.config["gateways"] = [{"interface": "en0", "address": "10.0.0.1", "subnet": "10.0.0.0/24"}]
        second = compile_policy(self.config)
        self.assertIn("on en0 inet proto icmp to 10.0.0.1 icmp-type echoreq no state", second)
        self.assertNotIn("192.168.1.1", second)
        self.assertNotIn("to 10.0.0.0/24", second)

    def test_router_access_does_not_open_general_dns_or_lan(self):
        self.config["gateways"] = [{"interface": "en0", "address": "192.168.1.1", "subnet": "192.168.1.0/24"}]
        rules = compile_policy(self.config)
        self.assertNotIn("inet to 192.168.1.1 no state", rules)
        self.assertNotIn("port 53", rules)
        self.assertIn("proto icmp to 192.168.1.1", rules)
        self.assertIn("to 192.168.1.1 port { 80, 443 }", rules)
        self.assertIn("port 68 to 192.168.1.1 port 67", rules)

    def test_gateway_snapshot_validation(self):
        for dev, address, subnet in [("utun3", "192.168.1.1", "192.168.1.0/24"),
                                     ("en1", "192.168.1.1", "192.168.1.0/24"),
                                     ("en0", "8.8.8.8", "8.8.8.0/24"),
                                     ("en0", "192.168.2.1", "192.168.1.0/24"),
                                     ("en0", "192.168.1.255", "192.168.1.0/24")]:
            self.config["gateways"] = [{"interface": dev, "address": address, "subnet": subnet}]
            with self.subTest(address=address, dev=dev), self.assertRaises(PolicyError):
                compile_policy(self.config)

    def test_deterministic(self):
        self.config["physical"] = ["en1", "en0", "en0"]
        first = compile_policy(self.config)
        self.config["physical"].reverse()
        self.assertEqual(first, compile_policy(self.config))


if __name__ == "__main__":
    unittest.main()
