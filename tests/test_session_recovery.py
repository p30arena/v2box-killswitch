from dataclasses import replace
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from health import HealthResult
from session_recovery import RecoveryView, SessionRecovery

UUID = "00000000-0000-0000-0000-000000000000"


class Commands:
    service_uuid = UUID
    def __init__(self): self.state = "Disconnected"; self.calls = []; self.status_reads = 0
    def status(self): self.status_reads += 1; return self.state
    def start(self): self.calls.append("start"); return True
    def stop(self): self.calls.append("stop"); return True


class Probe:
    def __init__(self): self.calls = []; self.hook = None; self.health = "unusable"
    def check(self, tunnel):
        self.calls.append(tunnel)
        if self.hook: self.hook()
        return HealthResult(self.health, "probe_failed")


class SessionRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.commands = Commands()
        self.probe = Probe()
        self.view = RecoveryView(UUID, "policy_epoch_0001", None, None, True, True, True, True, "approved")
        self.reads = 0
        self.reader_hook = None
        self.session = SessionRecovery(UUID, self.commands, self.context, self.probe)

    def context(self):
        self.reads += 1
        if self.reader_hook: self.reader_hook(self.reads)
        return self.view

    def connected(self):
        self.commands.state = "Connected"
        self.view = replace(self.view, tunnel="utun3", tunnel_identity="connection_id_0001")

    def restarting(self, **options):
        self.session = SessionRecovery(UUID, self.commands, self.context, self.probe,
                                       allow_connected_restart=True, **options)

    def test_disconnected_start_is_guarded_and_does_not_probe(self):
        result = self.session.tick(0)
        self.assertEqual(result.action, "start")
        self.assertEqual(self.commands.calls, ["start"])
        self.assertEqual(self.probe.calls, [])
        self.assertEqual(self.reads, 5)

    def test_off_or_unverified_policy_never_reads_vpn_or_probes(self):
        original = self.view
        for field in ("requested_enabled", "pf_enabled", "gate_verified", "approved_policy_matches"):
            self.view = replace(original, **{field: False})
            self.assertEqual(self.session.tick(self.reads).state, "context_unverified")
        self.assertEqual(self.commands.status_reads, 0)
        self.assertEqual(self.commands.calls, [])
        self.assertEqual(self.probe.calls, [])

    def test_quarantine_cannot_authorize_reconnect(self):
        self.view = replace(self.view, policy_mode="quarantine")
        self.assertEqual(self.session.tick(0).state, "context_unverified")
        self.assertEqual(self.commands.calls, [])

    def test_plain_on_status_is_not_an_authenticated_context(self):
        self.view = {"state": "on", "can_reconnect": "true"}
        self.assertEqual(self.session.tick(0).state, "context_unverified")
        self.assertEqual(self.commands.status_reads, 0)

    def test_malformed_flags_and_identities_are_rejected(self):
        original = self.view
        variants = [{"pf_enabled": 1}, {"requested_enabled": "true"}, {"epoch": ""},
                    {"service_uuid": "11111111-1111-1111-1111-111111111111"},
                    {"tunnel": "en0", "tunnel_identity": "connection_id_0001"},
                    {"tunnel": "utun3", "tunnel_identity": None}]
        for now, changes in enumerate(variants):
            self.view = replace(original, **changes)
            self.assertEqual(self.session.tick(now).state, "context_unverified")
        self.assertEqual(self.commands.calls, [])

    def test_observed_disable_at_each_revalidation_prevents_command(self):
        for boundary in (2, 3, 4, 5):
            self.setUp()
            def hook(count):
                if count == boundary: self.view = replace(self.view, requested_enabled=False)
            self.reader_hook = hook
            self.assertEqual(self.session.tick(0).state, "context_changed")
            self.assertEqual(self.commands.calls, [])

    def test_context_reader_failure_is_safe_and_does_not_escape_private_text(self):
        def broken(count): raise RuntimeError("secret provider configuration")
        self.reader_hook = broken
        result = self.session.tick(0)
        self.assertEqual(result.state, "context_unverified")
        self.assertNotIn("secret", repr(result))
        self.assertEqual(self.commands.calls, [])

    def test_connected_restart_is_off_by_default_without_probe_traffic(self):
        self.connected()
        for now in range(5): self.session.tick(now)
        self.assertEqual(self.probe.calls, [])
        self.assertEqual(self.commands.calls, [])

    def test_unusable_probe_requires_threshold_then_guarded_stop_start(self):
        self.connected(); self.restarting()
        self.session.tick(0); self.session.tick(1)
        self.assertEqual(self.commands.calls, [])
        self.assertEqual(self.session.tick(2).action, "stop")
        self.commands.state = "Disconnected"
        self.view = replace(self.view, tunnel=None, tunnel_identity=None, epoch="policy_epoch_0002")
        self.assertEqual(self.session.tick(7).action, "start")
        self.assertEqual(self.commands.calls, ["stop", "start"])

    def test_disable_during_probe_discards_evidence(self):
        self.connected(); self.restarting(unhealthy_threshold=1)
        self.probe.hook = lambda: setattr(self, "view", replace(self.view, requested_enabled=False))
        self.assertEqual(self.session.tick(0).state, "context_changed")
        self.assertEqual(self.commands.calls, [])

    def test_epoch_change_during_probe_discards_evidence(self):
        self.connected(); self.restarting(unhealthy_threshold=1)
        self.probe.hook = lambda: setattr(self, "view", replace(self.view, epoch="policy_epoch_0002"))
        self.assertEqual(self.session.tick(0).state, "context_changed")
        self.assertEqual(self.commands.calls, [])

    def test_reused_tunnel_name_with_new_identity_resets_bad_health(self):
        self.connected(); self.restarting()
        self.session.tick(0); self.session.tick(1)
        self.view = replace(self.view, tunnel_identity="connection_id_0002")
        self.session.tick(2); self.session.tick(3)
        self.assertEqual(self.commands.calls, [])
        self.assertEqual(self.session.tick(4).action, "stop")

    def test_unverified_health_never_stops_connected_vpn(self):
        self.connected(); self.restarting()
        self.probe.health = "unverified"
        for now in range(10): self.session.tick(now)
        self.assertEqual(self.commands.calls, [])

    def test_probe_exception_is_unverified_not_unusable(self):
        self.connected(); self.restarting(unhealthy_threshold=1)
        def broken(): raise RuntimeError("private probe output")
        self.probe.hook = broken
        self.assertEqual(self.session.tick(0).state, "health_unverified")
        self.assertEqual(self.commands.calls, [])

    def test_connected_without_verified_tunnel_cannot_probe(self):
        self.commands.state = "Connected"; self.restarting()
        self.assertEqual(self.session.tick(0).state, "tunnel_unverified")
        self.assertEqual(self.probe.calls, [])
        self.assertEqual(self.commands.calls, [])

    def test_local_status_change_before_command_prevents_action(self):
        self.reader_hook = lambda count: setattr(self.commands, "state", "Connected") if count == 4 else None
        self.assertEqual(self.session.tick(0).state, "context_changed")
        self.assertEqual(self.commands.calls, [])

    def test_adapter_cannot_change_target_service(self):
        self.reader_hook = lambda count: setattr(self.commands, "service_uuid", "other") if count == 5 else None
        self.assertEqual(self.session.tick(0).state, "context_changed")
        self.assertEqual(self.commands.calls, [])

    def test_backoff_and_cooldown_remain_bounded(self):
        for now in (0, 5, 15, 35): self.session.tick(now)
        self.assertEqual(self.session.tick(75).state, "cooldown")
        self.session.tick(100)
        self.assertEqual(len(self.commands.calls), 4)
        self.session.tick(375)
        self.assertEqual(len(self.commands.calls), 5)

    def test_recursive_tick_is_busy_not_a_second_command(self):
        results = []
        self.reader_hook = lambda count: results.append(self.session.tick(0)) if count == 1 else None
        self.session.tick(0)
        self.assertEqual(results[0].state, "busy")
        self.assertEqual(self.commands.calls, ["start"])

    def test_invalid_clock_is_rejected_before_callbacks(self):
        for now in (True, float("inf"), float("nan")):
            with self.assertRaises(ValueError): self.session.tick(now)
        self.assertEqual(self.reads, 0)
        self.session.tick(10)
        reads = self.reads
        with self.assertRaises(ValueError): self.session.tick(9)
        self.assertEqual(self.reads, reads)

    def test_configuration_requires_matching_approved_adapter(self):
        with self.assertRaises(ValueError): SessionRecovery("not a UUID", self.commands, self.context)
        self.commands.service_uuid = "other"
        with self.assertRaises(ValueError): SessionRecovery(UUID, self.commands, self.context)


if __name__ == "__main__": unittest.main()
