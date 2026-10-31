import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from gateways import discover, discover_active, parse_snapshot, physical_devices
from policy import PolicyError

ROUTE = "   gateway: 192.168.1.1\n  interface: en0\n"
INFO = "en0: flags=8863<UP>\n\tinet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255\n\tstatus: active\n"
PORTS = "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n\nHardware Port: Thunderbolt Bridge\nDevice: bridge0\n"


class GatewayTests(unittest.TestCase):
    def test_parses_scoped_route(self):
        self.assertEqual(parse_snapshot("en0", ROUTE, INFO),
                         {"interface": "en0", "address": "192.168.1.1", "subnet": "192.168.1.0/24"})

    def test_hardware_inventory_filters_virtual_ports(self):
        self.assertEqual(physical_devices(PORTS), ["en0"])

    def test_discover_active_reads_router_for_each_physical_port(self):
        en1_info = INFO.replace("en0", "en1").replace("192.168.1", "10.0.0")
        en1_route = ROUTE.replace("en0", "en1").replace("192.168.1", "10.0.0")
        def run(args):
            if args == ["/usr/sbin/networksetup", "-listallhardwareports"]:
                return SimpleNamespace(returncode=0, stdout=PORTS + "\nHardware Port: Ethernet\nDevice: en1\n")
            if args == ["/sbin/ifconfig", "en0"]:
                return SimpleNamespace(returncode=0, stdout=INFO)
            if args == ["/sbin/ifconfig", "en1"]:
                return SimpleNamespace(returncode=0, stdout=en1_info)
            if "-ifscope" in args and "en0" in args:
                return SimpleNamespace(returncode=0, stdout=ROUTE)
            if "-ifscope" in args and "en1" in args:
                return SimpleNamespace(returncode=0, stdout=en1_route)
            raise AssertionError(args)
        found = discover_active(run)
        self.assertEqual([(x["interface"], x["address"]) for x in found],
                         [("en0", "192.168.1.1"), ("en1", "10.0.0.1")])

    def test_rejects_tunnel_route(self):
        with self.assertRaises(PolicyError):
            parse_snapshot("en0", ROUTE.replace("en0", "utun3"), INFO)

    def test_rejects_inactive_or_offlink(self):
        for route, info in [(ROUTE, INFO.replace("status: active", "status: inactive")),
                            (ROUTE.replace("192.168.1.1", "10.0.0.1"), INFO)]:
            with self.assertRaises(PolicyError):
                parse_snapshot("en0", route, info)

    def test_discovery_uses_only_scoped_read_commands(self):
        calls = []
        def run(args):
            calls.append(args)
            return SimpleNamespace(returncode=0, stdout=INFO if args[0] == "/sbin/ifconfig" else ROUTE)
        discover("en0", run)
        self.assertEqual(calls, [["/sbin/route", "-n", "get", "-ifscope", "en0", "default"],
                                 ["/sbin/ifconfig", "en0"],
                                 ["/sbin/route", "-n", "get", "-ifscope", "en0", "default"]])

    def test_rejects_failed_commands(self):
        with self.assertRaises(PolicyError):
            discover("en0", lambda args: SimpleNamespace(returncode=1, stdout=""))

    def test_rejects_observed_network_change(self):
        replies = iter([ROUTE, INFO + "\tinet 10.0.0.100 netmask 0xffffff00\n",
                        ROUTE.replace("192.168.1.1", "10.0.0.1")])
        with self.assertRaises(PolicyError):
            discover("en0", lambda args: SimpleNamespace(returncode=0, stdout=next(replies)))


if __name__ == "__main__":
    unittest.main()
