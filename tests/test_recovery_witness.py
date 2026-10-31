import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from controller import ControllerError
from recovery_broker import Completion
from recovery_store import MAX_BYTES, PendingCommandStore
from recovery_witness import ChildWitnessStore, WitnessGate

VALUE = {"ticket": "a"*32, "uid": 501,
         "worker": {"pid": 101, "birth_seconds": 1234, "birth_microseconds": 10},
         "child": {"pid": 102, "birth_seconds": 1235, "birth_microseconds": 20}}
PENDING = {key: VALUE[key] for key in ("ticket", "uid")}
PROOF = Completion(VALUE["ticket"], VALUE["uid"], True, 0)  # Fake supervisor, not IPC data.


class WitnessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / "state"; self.directory.mkdir(mode=0o700)
        self.pending = PendingCommandStore(self.directory, "boot-one", expected_uid=os.getuid())
        self.witness = self.restarted()
        self.path = self.directory / "recovery-child-witness.json"
        self.pending.write(PENDING)
        self.authorization = []
        self.gate = WitnessGate(self.pending, self.witness, self.authorize)

    def restarted(self, boot="boot-one"):
        return ChildWitnessStore(self.directory, boot, expected_uid=os.getuid())

    def authorize(self):
        self.authorization.append(True)
        return True

    def raw(self, value):
        self.path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        self.path.chmod(0o600)

    def test_grant_persists_before_returning_exec(self):
        self.assertEqual(self.gate.grant(VALUE), ("EXEC " + VALUE["ticket"] + "\n").encode())
        record = self.restarted().read()
        self.assertEqual(record["phase"], "grant_recorded")
        self.assertIsNone(record["exit_code"])
        self.assertEqual(record["child"], VALUE["child"])
        self.assertEqual(self.pending.read(), PENDING)
        self.assertEqual(len(self.authorization), 2)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_no_matching_pending_no_witness_or_exec(self):
        self.pending.clear(PENDING["ticket"], PENDING["uid"])
        with self.assertRaises(ControllerError): self.gate.grant(VALUE)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.authorization, [])

    def test_pre_and_post_write_authorization_checks(self):
        for responses, exists in (([False], False), ([True, False], True), ([1], False)):
            if self.path.exists(): self.path.unlink()
            gate = WitnessGate(self.pending, self.witness, lambda: responses.pop(0))
            with self.assertRaises(ControllerError): gate.grant(VALUE)
            self.assertEqual(self.path.exists(), exists)
            self.assertEqual(self.pending.read(), PENDING)

    def test_unresolved_identity_cannot_be_overwritten(self):
        self.witness.record_grant(VALUE)
        before = self.path.read_bytes()
        for field in ("ticket", "uid", "worker", "child"):
            value = copy.deepcopy(VALUE)
            if field == "ticket": value[field] = "b"*32
            elif field == "uid": value[field] = 502
            else: value[field]["birth_microseconds"] += 1
            with self.assertRaises(ControllerError): self.witness.record_grant(value)
            self.assertEqual(self.path.read_bytes(), before)

    def test_same_grant_retry_commits_again(self):
        self.witness.record_grant(VALUE)
        with patch("recovery_store.os.fsync", wraps=os.fsync) as sync:
            self.witness.record_grant(VALUE)
            self.assertEqual(sync.call_count, 2)

    def test_write_failure_before_replace_never_returns_exec(self):
        with patch("recovery_store.os.replace", side_effect=OSError("replace failed")):
            with self.assertRaises(OSError): self.gate.grant(VALUE)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.pending.read(), PENDING)
        self.assertEqual(list(self.directory.glob(".recovery-child-witness-*")), [])

    def test_file_fsync_failure_never_releases_exec(self):
        with patch("recovery_store.os.fsync", side_effect=OSError("file sync failed")):
            with self.assertRaises(OSError): self.gate.grant(VALUE)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.pending.read(), PENDING)
        self.assertEqual(list(self.directory.glob(".recovery-child-witness-*")), [])

    def test_directory_fsync_failure_is_not_rollback_or_exec_permission(self):
        original = os.fsync
        calls = []
        def sync(fd):
            calls.append(fd)
            if len(calls) == 2: raise OSError("directory durability uncertain")
            return original(fd)
        with patch("recovery_store.os.fsync", side_effect=sync):
            with self.assertRaises(OSError): self.gate.grant(VALUE)
        self.assertEqual(self.restarted().read()["phase"], "grant_recorded")
        self.assertEqual(self.pending.read(), PENDING)
        # A retry must perform fsync again rather than assume visible == durable.
        self.assertTrue(self.gate.grant(VALUE).startswith(b"EXEC "))

    def test_readback_change_cannot_release_exec(self):
        with patch.object(self.witness, "read", return_value=None):
            with self.assertRaises(ControllerError): self.gate.grant(VALUE)
        self.assertEqual(self.pending.read(), PENDING)

    def test_pending_change_during_write_cannot_release_exec(self):
        original = self.witness.record_grant
        def record(value):
            result = original(value)
            self.pending.clear(PENDING["ticket"], PENDING["uid"])
            return result
        with patch.object(self.witness, "record_grant", side_effect=record):
            with self.assertRaises(ControllerError): self.gate.grant(VALUE)

    def test_directory_path_replacement_cannot_release_exec(self):
        original = os.replace
        old = self.root / "old-state"
        def replace(source, target, **kwargs):
            result = original(source, target, **kwargs)
            self.directory.rename(old)
            self.directory.mkdir(mode=0o700)
            return result
        with patch("recovery_store.os.replace", side_effect=replace):
            with self.assertRaises(ControllerError): self.gate.grant(VALUE)
        self.assertTrue((old / self.path.name).exists())
        self.assertFalse(self.path.exists())

    def test_completion_persists_before_broker_clears_pending(self):
        self.gate.grant(VALUE)
        self.gate.finish(VALUE, Completion(VALUE["ticket"], 501, True, -9))
        self.assertEqual(self.witness.read()["phase"], "completed")
        self.assertEqual(self.witness.read()["exit_code"], -9)
        self.assertEqual(self.pending.read(), PENDING)

    def test_completion_write_failure_never_clears_pending(self):
        self.gate.grant(VALUE)
        with patch("recovery_store.os.replace", side_effect=OSError("completion write failed")):
            with self.assertRaises(OSError): self.gate.finish(VALUE, PROOF)
        self.assertEqual(self.pending.read(), PENDING)
        self.assertEqual(self.witness.read()["phase"], "grant_recorded")

    def test_completion_directory_sync_uncertainty_keeps_pending(self):
        self.gate.grant(VALUE)
        original = os.fsync
        calls = []
        def sync(fd):
            calls.append(fd)
            if len(calls) == 2: raise OSError("completion sync uncertain")
            return original(fd)
        with patch("recovery_store.os.fsync", side_effect=sync):
            with self.assertRaises(OSError): self.gate.finish(VALUE, PROOF)
        self.assertEqual(self.witness.read()["phase"], "completed")
        self.assertEqual(self.pending.read(), PENDING)
        self.gate.finish(VALUE, PROOF)
        self.assertEqual(self.pending.read(), PENDING)

    def test_finish_while_protection_off_does_not_reauthorize_or_enable(self):
        self.gate.grant(VALUE)
        def off(): raise AssertionError("completion must not authorize execution")
        self.gate.authorize = off
        self.gate.finish(VALUE, PROOF)
        self.assertEqual(self.witness.read()["phase"], "completed")
        self.assertEqual(self.pending.read(), PENDING)

    def broker(self):
        from recovery_broker import Completion, Context, RecoveryBroker
        def execute(**request):
            self.assertTrue(self.gate.grant(VALUE).startswith(b"EXEC "))
            # Model ONLY: native proof/transport is not implemented here.
            return self.gate.finish(VALUE, Completion(request["ticket"], request["uid"], True, 0))
        transaction = threading.Lock()
        return RecoveryBroker(lambda: transaction, self.pending,
            lambda: Context("00000000-0000-0000-0000-000000000000", 501, True,
                            True, True, True, "approved", "Disconnected"),
            execute, lambda: {"state": "off"}, new_ticket=lambda: VALUE["ticket"])

    def test_broker_clears_only_after_completed_witness(self):
        from recovery_broker import Peer
        self.pending.clear(PENDING["ticket"], PENDING["uid"])
        self.assertEqual(self.broker().request("start", Peer(501, True)).state, "completed")
        self.assertEqual(self.witness.read()["phase"], "completed")
        self.assertIsNone(self.pending.read())

    def test_pending_clear_failure_preserves_completed_witness(self):
        from recovery_broker import Completion, Peer
        self.pending.clear(PENDING["ticket"], PENDING["uid"])
        broker = self.broker()
        with patch.object(self.pending, "clear", side_effect=OSError("clear failed")):
            self.assertEqual(broker.request("start", Peer(501, True)).state, "reconciliation_required")
        self.assertEqual(self.restarted().read()["phase"], "completed")
        self.assertEqual(self.pending.read(), PENDING)
        # Internal trusted proof only, not a caller-supplied XPC completion.
        WitnessGate(self.pending, self.restarted(), self.authorize).finish(VALUE, PROOF)
        self.assertEqual(broker.reconcile(Completion(VALUE["ticket"], 501, True, 0)).state, "reconciled")
        self.assertIsNone(self.pending.read())

    def test_mismatched_completion_never_clears_pending(self):
        self.gate.grant(VALUE)
        for field in ("ticket", "uid", "worker", "child"):
            value = copy.deepcopy(VALUE)
            if field == "ticket": value[field] = "b"*32
            elif field == "uid": value[field] = 502
            else: value[field]["pid"] += 100
            with self.assertRaises(ControllerError): self.gate.finish(value, PROOF)
            self.assertEqual(self.pending.read(), PENDING)

    def test_unknown_or_mismatched_proof_never_records_completion(self):
        self.gate.grant(VALUE)
        for proof in (0, None, {"terminated": True}, Completion(VALUE["ticket"], 501, False, 0),
                      Completion("b"*32, 501, True, 0), Completion(VALUE["ticket"], True, True, 0)):
            with self.assertRaises(ControllerError): self.gate.finish(VALUE, proof)
            self.assertEqual(self.witness.read()["phase"], "grant_recorded")
            self.assertEqual(self.pending.read(), PENDING)

    def test_completed_ticket_cannot_be_downgraded_or_change_exit(self):
        self.witness.record_grant(VALUE)
        self.witness.complete(VALUE, 0)
        with self.assertRaises(ControllerError): self.witness.record_grant(VALUE)
        with self.assertRaises(ControllerError): self.witness.complete(VALUE, -9)
        new = dict(VALUE, ticket="b"*32)
        self.assertEqual(self.witness.record_grant(new)["ticket"], "b"*32)

    def test_unresolved_other_boot_refuses_overwrite_and_completion(self):
        self.witness.record_grant(VALUE)
        other = self.restarted("boot-two")
        for action in (other.read, lambda: other.record_grant(VALUE), lambda: other.complete(VALUE, 0)):
            with self.assertRaises(ControllerError): action()
        self.witness.complete(VALUE, 0)
        self.assertEqual(other.read()["phase"], "completed")
        self.assertEqual(other.record_grant(dict(VALUE, ticket="b"*32))["boot_id"], "boot-two")

    def test_mixed_boot_stores_rejected(self):
        with self.assertRaises(ControllerError): WitnessGate(self.pending, self.restarted("other"), self.authorize)

    def test_invalid_identity_exit_and_unknown_fields_rejected(self):
        for field, replacement in (("pid", 0), ("pid", True), ("pid", 1 << 31),
                                   ("birth_seconds", -1), ("birth_microseconds", 1_000_000)):
            value = copy.deepcopy(VALUE); value["child"][field] = replacement
            with self.assertRaises(ControllerError): self.witness.record_grant(value)
        value = dict(VALUE, untrusted="field")
        with self.assertRaises(ControllerError): self.witness.record_grant(value)
        value = dict(VALUE, child=VALUE["worker"])
        with self.assertRaises(ControllerError): self.witness.record_grant(value)
        self.witness.record_grant(VALUE)
        for code in (None, True, "0", -128, 256):
            with self.assertRaises(ControllerError): self.witness.complete(VALUE, code)

    def test_malformed_null_duplicate_oversized_and_wrong_phase_refused(self):
        record = self.witness.record_grant(VALUE)
        for raw in (b"null", b"{}", b'{"version":1,"version":1}', b"x"*(MAX_BYTES+1)):
            self.raw(raw)
            with self.assertRaises(ControllerError): self.witness.read()
        for update in ({"phase": "running"}, {"version": True}, {"exit_code": 0},
                       {"phase": "completed", "exit_code": None}):
            self.raw(dict(record, **update))
            with self.assertRaises(ControllerError): self.witness.read()

    def test_unsafe_files_and_directory_refused(self):
        self.witness.record_grant(VALUE)
        self.path.chmod(0o644)
        with self.assertRaises(ControllerError): self.witness.read()
        self.path.chmod(0o600)
        link = self.root / "hardlink"; os.link(self.path, link)
        with self.assertRaises(ControllerError): self.witness.read()
        link.unlink(); self.path.unlink()
        target = self.root / "target"; target.write_text("private"); target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaises(OSError): self.witness.read()
        self.path.unlink(); os.mkfifo(self.path, 0o600)
        with self.assertRaises(ControllerError): self.witness.read()
        self.path.unlink(); self.directory.chmod(0o755)
        with self.assertRaises(ControllerError): self.witness.read()

    def test_fresh_subprocess_reads_record_without_inventing_completion(self):
        self.gate.grant(VALUE)
        source = str(Path(__file__).resolve().parents[1] / "src")
        code = ("import sys; sys.path.insert(0, sys.argv[1]); from recovery_witness import ChildWitnessStore; "
                "s=ChildWitnessStore(sys.argv[2], 'boot-one', expected_uid=int(sys.argv[3])); "
                "r=s.read(); assert r['phase']=='grant_recorded' and r['exit_code'] is None")
        subprocess.run([sys.executable, "-I", "-c", code, source, str(self.directory), str(os.getuid())],
                       check=True, capture_output=True, timeout=5)
        self.assertEqual(self.pending.read(), PENDING)


if __name__ == "__main__": unittest.main()
