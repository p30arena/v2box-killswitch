from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from recovery import Recovery
from vpn_commands import VPNCommands


class Commands:
    def __init__(self): self.calls = []; self.fail = False
    def start(self): self.calls.append("start"); return not self.fail
    def stop(self): self.calls.append("stop"); return not self.fail


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.commands = Commands()
        self.recovery = Recovery(self.commands)

    def test_disconnected_starts_immediately_with_backoff(self):
        self.assertEqual(self.recovery.tick(0, "Disconnected", "unverified", True).action, "start")
        self.assertEqual(self.recovery.tick(1, "Disconnected", "unverified", True).state, "backoff")
        self.assertEqual(self.recovery.tick(5, "Disconnected", "unverified", True).next_due, 15)
        self.assertEqual(self.commands.calls, ["start", "start"])

    def test_healthy_never_restarts(self):
        for now in range(20):
            self.assertEqual(self.recovery.tick(now, "Connected", "usable", True).state, "healthy")
        self.assertEqual(self.commands.calls, [])

    def test_unknown_health_does_not_restart_connected(self):
        for now in range(20): self.recovery.tick(now, "Connected", "unverified", True)
        self.assertEqual(self.commands.calls, [])

    def test_unhealthy_requires_repeated_evidence_then_stop_start(self):
        for now in (0, 1): self.recovery.tick(now, "Connected", "unusable", True)
        self.assertEqual(self.commands.calls, [])
        self.assertEqual(self.recovery.tick(2, "Connected", "unusable", True).action, "stop")
        self.assertEqual(self.recovery.tick(7, "Disconnected", "unverified", True).action, "start")
        self.assertEqual(self.commands.calls, ["stop", "start"])

    def test_no_network_changes_without_verified_enforcement(self):
        for now, status in enumerate(("Disconnected", "Connected", "Connecting")):
            self.recovery.tick(now, status, "unusable", False)
        self.assertEqual(self.commands.calls, [])

    def test_transition_timeout(self):
        self.recovery.tick(0, "Connecting", "unverified", True)
        self.recovery.tick(59, "Connecting", "unverified", True)
        self.assertEqual(self.commands.calls, [])
        self.assertEqual(self.recovery.tick(60, "Connecting", "unverified", True).action, "stop")

    def test_bounded_burst_and_cooldown(self):
        for now in (0, 5, 15, 35): self.recovery.tick(now, "Disconnected", "unverified", True)
        self.assertEqual(len(self.commands.calls), 4)
        result = self.recovery.tick(75, "Disconnected", "unverified", True)
        self.assertEqual(result.state, "cooldown")
        self.assertEqual(result.next_due, 375)
        self.recovery.tick(100, "Disconnected", "unverified", True)
        self.assertEqual(len(self.commands.calls), 4)
        self.recovery.tick(375, "Disconnected", "unverified", True)
        self.assertEqual(len(self.commands.calls), 5)

    def test_failed_start_respects_backoff(self):
        self.commands.fail = True
        self.assertEqual(self.recovery.tick(0, "Disconnected", "unverified", True).state, "command_failed")
        self.recovery.tick(1, "Disconnected", "unverified", True)
        self.assertEqual(self.commands.calls, ["start"])

    def test_unknown_vpn_status_never_issues_commands(self):
        self.recovery.tick(0, "Unknown", "unusable", True)
        self.assertEqual(self.commands.calls, [])

    def test_healthy_resets_retry_budget(self):
        self.recovery.tick(0, "Disconnected", "unverified", True)
        self.assertEqual(self.recovery.tick(1, "Connected", "usable", True).attempts, 0)

    def test_bad_clock_rejected(self):
        self.recovery.tick(10, "Connected", "usable", True)
        for now in (9, float("nan")):
            with self.assertRaises(ValueError): self.recovery.tick(now, "Disconnected", "unverified", True)


class VPNCommandTests(unittest.TestCase):
    UUID = "00000000-0000-0000-0000-000000000000"

    def test_only_fixed_native_commands_with_deadline(self):
        calls = []
        def run(args, timeout):
            calls.append((args, timeout))
            return SimpleNamespace(returncode=0, stdout="Connected\nprivate provider payload omitted")
        vpn = VPNCommands(self.UUID, run)
        self.assertTrue(vpn.start()); self.assertTrue(vpn.stop())
        self.assertEqual(vpn.status(), "Connected")
        self.assertEqual([x[0][2] for x in calls], ["start", "stop", "status"])
        self.assertTrue(all(x[1] == 8 for x in calls))

    def test_invalid_service_rejected_before_commands(self):
        with self.assertRaises(ValueError): VPNCommands("V2BOX; anything", None)

    def test_unrecognized_status_is_unknown(self):
        vpn = VPNCommands(self.UUID, lambda *a, **k: SimpleNamespace(returncode=0, stdout="mystery"))
        self.assertEqual(vpn.status(), "Unknown")


if __name__ == "__main__": unittest.main()
