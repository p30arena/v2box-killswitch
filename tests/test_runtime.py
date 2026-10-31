import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from controller import Controller, ControllerError, StateStore
from pf_driver import PFDriver, ANCHOR
from runtime import Runtime, read_trial_summary
from test_pf_driver import Kernel, Tokens
from test_gateways import ROUTE, INFO, PORTS


class Native:
    def __init__(self):
        self.pf = Kernel()
        self.pf.root = f'anchor "{ANCHOR}" quick all\nanchor "com.apple/*" all\n'
        self.states = ""
        self.skip = ""
        self.legacy = False
        self.status = "Connected"
        self.tunnel = "utun3"

    def run(self, args, input=None):
        out = None
        code = 0
        if args == ["/sbin/pfctl", "-s", "states"]: out = self.states
        elif args == ["/sbin/pfctl", "-s", "Interfaces", "-v"]: out = self.skip
        elif args[0] == "/sbin/pfctl": return self.pf.run(args, input)
        elif args == ["/usr/sbin/networksetup", "-listallhardwareports"]: out = PORTS
        elif args == ["/sbin/ifconfig", "en0"]: out = INFO
        elif args == ["/sbin/ifconfig", "-v"]: out = f'{self.tunnel}: flags=0\n\tdesc:"VPN: V2BOX" NetworkExtension type:VPN\n'
        elif args[:3] == ["/sbin/route", "-n", "get"]: out = ROUTE
        elif args[:3] == ["/usr/sbin/scutil", "--nc", "status"]: out = self.status
        elif args[:2] == ["/bin/launchctl", "print"]: out = ""; code = 0 if self.legacy else 1
        else: raise AssertionError(args)
        return SimpleNamespace(returncode=code, stdout=out, stderr="")


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.native = Native()
        self.controller = Controller(StateStore(self.temp.name), PFDriver(self.native.run, Tokens()))
        self.config = {"service_uuid": "00000000-0000-0000-0000-000000000000", "service_name": "V2BOX", "profile": "one",
                       "inventory": {"version": 1, "profiles": {"one": {
                           "revision": "1", "expires_at": 2000,
                           "endpoints": [{"address": "1.1.1.1", "port": 443, "protocol": "tcp"}]}}}}
        self.runtime = Runtime(self.controller, self.native.run, lambda: copy.deepcopy(self.config), now=lambda: 1000)

    def test_trial_status_is_allowlisted(self):
        self.runtime.trial_reader = lambda: {"verdict": "limited_ipv4_pass"}
        self.assertEqual(self.runtime.dispatch("status")["trial_verdict"], "limited_ipv4_pass")
        self.runtime.trial_reader = lambda: {"verdict": "arbitrary data"}
        self.assertEqual(self.runtime.dispatch("status")["trial_verdict"], "inconclusive")

    def test_no_trial_report_is_not_started(self):
        self.assertEqual(read_trial_summary(Path(self.temp.name))["verdict"], "not_started")

    def test_trial_pass_without_confirmation_marker_is_inconclusive(self):
        import json
        directory = Path(self.temp.name) / "first-test"
        directory.mkdir()
        (directory / "observation.json").write_text(json.dumps({"verdict": "limited_ipv4_pass"}))
        self.assertEqual(read_trial_summary(Path(self.temp.name))["verdict"], "inconclusive")
        (directory / "confirmed").write_text("limited scope")
        self.assertEqual(read_trial_summary(Path(self.temp.name))["verdict"], "limited_ipv4_pass")

    def test_enable_status_disable_with_fake_kernel(self):
        self.assertEqual(self.runtime.dispatch("status")["can_enable"], "true")
        self.assertEqual(self.runtime.dispatch("enable")["state"], "on")
        self.assertIn("on utun3", self.native.pf.rules)
        self.assertEqual(self.runtime.dispatch("status")["state"], "on")
        self.assertEqual(self.runtime.dispatch("disable")["state"], "off")
        self.assertEqual(self.native.pf.rules, "")

    def test_auto_connect_target_only_advertised_with_exact_approved_enforcement(self):
        off = self.runtime.dispatch("status")
        self.assertEqual(off["can_auto_connect"], "false")
        self.assertNotIn("auto_connect_service_uuid", off)
        self.runtime.dispatch("enable")
        status = self.runtime.dispatch("status")
        self.assertEqual(status["can_auto_connect"], "true")
        self.assertEqual(status["auto_connect_service_uuid"], self.config["service_uuid"])
        self.assertEqual(status["can_reconnect"], "false")  # No privileged runner.
        self.runtime.dispatch("disable")
        self.assertEqual(self.runtime.dispatch("status")["can_auto_connect"], "false")

    def test_auto_connect_requires_uuid_and_normalizes_it(self):
        self.config["service_uuid"] = "00000000-0000-0000-0000-00000000abcd"
        self.runtime.dispatch("enable")
        self.assertEqual(self.runtime.dispatch("status")["auto_connect_service_uuid"],
                         "00000000-0000-0000-0000-00000000ABCD")
        self.config["service_uuid"] = "not-a-service-id"
        status = self.runtime.dispatch("status")
        self.assertEqual(status["can_auto_connect"], "false")
        self.assertNotIn("auto_connect_service_uuid", status)

    def test_auto_connect_not_advertised_for_unknown_or_expired_approval(self):
        self.runtime.dispatch("enable")
        self.config["inventory"]["profiles"]["one"]["expires_at"] = 999
        status = self.runtime.dispatch("status")
        self.assertEqual(status["can_auto_connect"], "false")
        self.assertNotIn("auto_connect_service_uuid", status)

    def test_auto_connect_not_advertised_for_quarantine(self):
        self.runtime.dispatch("enable")
        self.config["profile"] = "unknown"
        self.runtime.dispatch("refresh")
        self.config["profile"] = "one"
        status = self.runtime.dispatch("status")
        self.assertEqual(status["policy_mode"], "quarantine")
        self.assertEqual(status["can_auto_connect"], "false")
        self.assertNotIn("auto_connect_service_uuid", status)

    def test_auto_connect_not_advertised_for_modified_kernel_policy(self):
        self.runtime.dispatch("enable")
        self.native.pf.rules += "pass out all\n"
        self.assertEqual(self.runtime.dispatch("status")["can_auto_connect"], "false")

    def test_auto_connect_not_advertised_with_pending_token(self):
        self.runtime.dispatch("enable")
        self.controller.backend.tokens.value = "pending"
        self.assertEqual(self.runtime.dispatch("status")["can_auto_connect"], "false")

    def test_pending_token_refuses_enable_before_rule_change(self):
        self.controller.backend.tokens.value = "pending"
        with self.assertRaises(ControllerError): self.runtime.dispatch("enable")
        self.assertEqual(self.native.pf.rules, "")
        self.assertEqual(self.runtime.dispatch("status")["can_enable"], "false")

    def test_disabled_pf_with_owned_token_refuses_enable_before_rule_change(self):
        self.controller.backend.tokens.value = "12345"
        self.native.pf.enabled = False
        with self.assertRaises(ControllerError): self.runtime.dispatch("enable")
        self.assertEqual(self.native.pf.rules, "")

    def test_existing_states_are_not_flushed_to_force_enable(self):
        self.native.states = "established unrelated state"
        with self.assertRaises(ControllerError): self.runtime.dispatch("enable")
        self.assertEqual(self.native.pf.rules, "")
        self.assertFalse(any("-F" in args for args, _ in self.native.pf.calls))

    def test_skip_interfaces_refuse_enable(self):
        self.native.skip = "en0 (skip)"
        with self.assertRaises(ControllerError): self.runtime.dispatch("enable")

    def test_legacy_reenabler_refuses_enable(self):
        self.native.legacy = True
        with self.assertRaises(ControllerError): self.runtime.dispatch("enable")

    def test_refresh_after_disable_never_reinstalls(self):
        self.runtime.dispatch("enable")
        self.runtime.dispatch("disable")
        self.native.pf.calls.clear()
        self.runtime.dispatch("refresh")
        self.assertEqual(self.native.pf.rules, "")
        self.assertFalse(any("-f" in args or "-E" in args for args, _ in self.native.pf.calls))

    def test_approved_endpoint_and_tunnel_changes_replace_rules(self):
        self.runtime.dispatch("enable")
        self.config["inventory"]["profiles"]["one"]["endpoints"][0]["address"] = "8.8.8.8"
        self.native.tunnel = "utun9"
        self.runtime.dispatch("refresh")
        self.assertIn("to 8.8.8.8", self.native.pf.rules)
        self.assertIn("on utun9", self.native.pf.rules)
        self.assertNotIn("utun3", self.native.pf.rules)
        self.assertNotIn("1.1.1.1", self.native.pf.rules)

    def test_unknown_profile_quarantines(self):
        self.runtime.dispatch("enable")
        self.config["profile"] = "unapproved"
        self.assertEqual(self.runtime.dispatch("refresh")["policy_mode"], "quarantine")
        self.assertNotIn("1.1.1.1", self.native.pf.rules)

    def test_discovery_failure_quarantines_before_reporting_failure(self):
        self.runtime.dispatch("enable")
        self.native.tunnel = "unknown"
        with self.assertRaises(ControllerError): self.runtime.dispatch("refresh")
        self.assertIn("v2box_quarantine", self.native.pf.rules)
        self.assertNotIn("1.1.1.1", self.native.pf.rules)

    def test_disconnected_removes_tunnel_pass_but_keeps_transport(self):
        self.runtime.dispatch("enable")
        self.native.status = "Disconnected"
        self.runtime.dispatch("refresh")
        self.assertNotIn("on utun3", self.native.pf.rules)
        self.assertIn("to 1.1.1.1", self.native.pf.rules)

    def test_modified_kernel_policy_does_not_report_on(self):
        self.runtime.dispatch("enable")
        self.native.pf.rules += "pass out all\n"
        self.assertEqual(self.runtime.dispatch("status")["state"], "error")


if __name__ == "__main__": unittest.main()
