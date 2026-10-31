from dataclasses import replace
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from recovery_broker import BrokerResult, Completion, Context, Peer, RecoveryBroker

UUID = "00000000-0000-0000-0000-000000000000"
TICKET = "a" * 32


class Pending:
    def __init__(self): self.value = None
    def read(self): return self.value
    def write(self, value): self.value = value


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.lock = threading.Lock()
        self.pending = Pending()
        self.peer = Peer(501, True)
        self.context = Context(UUID, 501, True, True, True, True, "approved", "Disconnected")
        self.calls = []
        self.events = []
        self.broker = self.make_broker()

    def execute(self, **request):
        self.calls.append(request)
        self.events.append("command_started")
        self.events.append("command_terminated")
        return Completion(request["ticket"], request["uid"], True, 0)

    def disable(self):
        self.events.append("disable_committed")
        self.context = replace(self.context, requested_enabled=False)
        return {"state": "off"}

    def make_broker(self, executor=None):
        return RecoveryBroker(lambda: self.lock, self.pending, lambda: self.context,
                              executor or self.execute, self.disable, new_ticket=lambda: TICKET)

    def test_fixed_scoped_request_and_completion(self):
        self.assertEqual(self.broker.request("start", self.peer), BrokerResult("completed", "start"))
        self.assertEqual(self.calls, [{"action": "start", "service_uuid": UUID, "uid": 501,
                                      "ticket": TICKET, "timeout": 8}])
        self.assertIsNone(self.pending.read())

    def test_disable_committed_first_prevents_command(self):
        self.assertEqual(self.broker.disable(), {"state": "off"})
        self.assertEqual(self.broker.request("start", self.peer).state, "not_eligible")
        self.assertEqual(self.calls, [])

    def test_disable_waits_for_started_command_to_terminate(self):
        started = threading.Event(); release = threading.Event(); disabling = threading.Event(); finished = threading.Event()
        outcomes = []
        def execute(**request):
            self.events.append("command_started"); started.set()
            if not release.wait(timeout=3): raise RuntimeError("test executor not released")
            self.events.append("command_terminated")
            return Completion(request["ticket"], request["uid"], True, 0)
        self.broker.execute_and_reap = execute
        worker = threading.Thread(target=lambda: outcomes.append(self.broker.request("start", self.peer)))
        def disable():
            disabling.set()
            outcomes.append(self.broker.disable()); finished.set()
        disabler = threading.Thread(target=disable)
        try:
            worker.start(); self.assertTrue(started.wait(timeout=2))
            disabler.start(); self.assertTrue(disabling.wait(timeout=2))
            self.assertFalse(finished.wait(timeout=0.05))
            self.assertTrue(self.context.requested_enabled)
            release.set()
            worker.join(timeout=3); disabler.join(timeout=3)
            self.assertFalse(worker.is_alive()); self.assertFalse(disabler.is_alive())
            self.assertEqual(self.events, ["command_started", "command_terminated", "disable_committed"])
            self.assertIn({"state": "off"}, outcomes)
        finally:
            release.set()
            if worker.ident: worker.join(timeout=3)
            if disabler.ident: disabler.join(timeout=3)

    def test_wrong_console_user_root_and_unauthenticated_peer_denied(self):
        for peer in (Peer(0, True), Peer(502, True), Peer(501, False), Peer(True, True), {"uid": 501}):
            self.assertEqual(self.broker.request("start", peer).state, "not_eligible")
        self.assertEqual(self.calls, [])

    def test_unverified_enforcement_and_quarantine_denied(self):
        original = self.context
        for changes in ({"pf_enabled": False}, {"gate_verified": False}, {"approved_policy_matches": False},
                        {"requested_enabled": False}, {"pf_enabled": 1}, {"policy_mode": "quarantine"}):
            self.context = replace(original, **changes)
            self.assertEqual(self.broker.request("start", self.peer).state, "not_eligible")
        self.assertEqual(self.calls, [])

    def test_only_start_stop_and_fresh_matching_status_allowed(self):
        for action in ("restart", "/bin/sh", "start;anything", None):
            self.assertEqual(self.broker.request(action, self.peer).state, "request_rejected")
        self.assertEqual(self.broker.request("stop", self.peer).state, "status_changed")
        self.context = replace(self.context, vpn_status="Connected")
        self.assertEqual(self.broker.request("start", self.peer).state, "status_changed")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.broker.request("stop", self.peer).state, "completed")

    def test_absent_executor_cannot_start_anything(self):
        self.broker.execute_and_reap = None
        self.assertEqual(self.broker.request("start", self.peer).state, "executor_unavailable")
        self.assertIsNone(self.pending.read())

    def test_pending_write_failure_prevents_spawn(self):
        with patch.object(self.pending, "write", side_effect=OSError("private storage error")):
            self.assertEqual(self.broker.request("start", self.peer).state, "pending_unavailable")
        self.assertEqual(self.calls, [])

    def test_timeout_is_not_termination_proof_and_does_not_unlock_disable(self):
        def timeout(**request): raise TimeoutError("private child state unknown")
        self.broker.execute_and_reap = timeout
        result = self.broker.request("start", self.peer)
        self.assertEqual(result.state, "reconciliation_required")
        self.assertNotIn("private", repr(result))
        self.assertIsNotNone(self.pending.read())
        self.assertEqual(self.broker.disable().state, "reconciliation_required")
        self.assertNotIn("disable_committed", self.events)

    def test_pending_survives_broker_reconstruction(self):
        self.pending.write({"ticket": TICKET, "uid": 501})
        restarted = self.make_broker()
        self.assertEqual(restarted.request("start", self.peer).state, "reconciliation_required")
        self.assertEqual(restarted.disable().state, "reconciliation_required")
        self.assertEqual(self.calls, [])

    def test_mismatched_or_unterminated_completion_remains_pending(self):
        for proof in (Completion("b"*32, 501, True, 0), Completion(TICKET, 0, True, 0),
                      Completion(TICKET, 501, False, 0), Completion(TICKET, 501, True, True), None):
            self.pending.value = None
            self.broker.execute_and_reap = lambda **request: proof
            self.assertEqual(self.broker.request("start", self.peer).state, "reconciliation_required")
            self.assertIsNotNone(self.pending.read())
            self.assertEqual(self.broker.disable().state, "reconciliation_required")

    def test_only_matching_supervisor_completion_reconciles(self):
        self.pending.write({"ticket": TICKET, "uid": 501})
        self.assertEqual(self.broker.reconcile(Completion(TICKET, 502, True, 0)).state, "reconciliation_required")
        self.assertEqual(self.broker.reconcile(Completion(TICKET, 501, True, 0)).state, "reconciled")
        self.assertEqual(self.broker.disable(), {"state": "off"})

    def test_pending_clear_failure_does_not_claim_completion(self):
        original = self.pending.write
        def write(value):
            if value is None: raise OSError("cannot clear durable state")
            original(value)
        with patch.object(self.pending, "write", side_effect=write):
            self.assertEqual(self.broker.request("start", self.peer).state, "reconciliation_required")
        self.assertIsNotNone(self.pending.read())

    def test_proven_command_failure_clears_pending_but_does_not_claim_success(self):
        self.broker.execute_and_reap = lambda **request: Completion(TICKET, 501, True, 1)
        self.assertEqual(self.broker.request("start", self.peer).state, "command_failed")
        self.assertIsNone(self.pending.read())
        self.assertEqual(self.broker.disable(), {"state": "off"})

    def test_disable_error_propagates_never_claims_off(self):
        self.broker.disable_protection = lambda: (_ for _ in ()).throw(RuntimeError("enforcement failure"))
        with self.assertRaises(RuntimeError): self.broker.disable()

    def test_corrupt_pending_cannot_be_reconciled_with_malformed_identity(self):
        self.pending.write({"ticket": TICKET, "uid": True})
        self.assertEqual(self.broker.reconcile(Completion(TICKET, 1, True, 0)).state, "reconciliation_required")


if __name__ == "__main__": unittest.main()
