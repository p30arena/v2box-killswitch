import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from controller import ControllerError
from recovery_store import MAX_BYTES, MAX_UID, PendingCommandStore

TICKET = "a" * 32
VALUE = {"ticket": TICKET, "uid": 501}


class RecoveryStoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / "state"; self.directory.mkdir(mode=0o700)
        self.store = self.restarted()
        self.path = self.directory / PendingCommandStore.NAME
        self.transaction = threading.Lock()
        self.enabled = True
        self.executions = []

    def restarted(self, boot="boot-one"):
        return PendingCommandStore(self.directory, boot, expected_uid=os.getuid())

    def write_raw(self, raw):
        self.path.write_bytes(raw if isinstance(raw, bytes) else raw.encode())
        self.path.chmod(0o600)

    def assert_no_temporaries(self):
        self.assertEqual(list(self.directory.glob(".recovery-pending-*")), [])

    def broker(self, store=None, executor=None):
        from recovery_broker import Completion, Context, RecoveryBroker
        def execute(**request):
            self.executions.append(request)
            if executor is not None: return executor(**request)
            return Completion(request["ticket"], request["uid"], True, 0)
        def disable():
            self.enabled = False
            return {"state": "off"}
        return RecoveryBroker(lambda: self.transaction, store or self.store,
            lambda: Context("00000000-0000-0000-0000-000000000000", 501, self.enabled,
                            True, True, True, "approved", "Disconnected"), execute, disable,
            new_ticket=lambda: TICKET)

    def test_real_store_broker_completion_clears_matching_fence(self):
        from recovery_broker import Peer
        broker = self.broker()
        self.assertEqual(broker.request("start", Peer(501, True)).state, "completed")
        self.assertIsNone(self.restarted().read())
        self.assertEqual(broker.disable(), {"state": "off"})
        self.assertEqual(len(self.executions), 1)

    def test_real_store_broker_restart_blocks_until_supervised_reconciliation(self):
        from recovery_broker import Completion, Peer
        def timeout(**request): raise TimeoutError("fake unknown child")
        self.assertEqual(self.broker(executor=timeout).request("start", Peer(501, True)).state, "reconciliation_required")
        restarted = self.broker(store=self.restarted())
        self.assertEqual(restarted.request("start", Peer(501, True)).state, "reconciliation_required")
        self.assertEqual(restarted.disable(), {"state": "off"})
        self.assertFalse(self.enabled)
        self.assertEqual(self.store.read(), VALUE)
        self.assertEqual(len(self.executions), 1)
        self.assertEqual(restarted.reconcile(Completion(TICKET, 501, True, 0)).state, "reconciled")
        self.assertEqual(restarted.disable(), {"state": "off"})

    def test_real_store_broker_does_not_execute_after_uncertain_pending_commit(self):
        from recovery_broker import Peer
        original = os.fsync
        count = 0
        def fsync(fd):
            nonlocal count
            count += 1
            if count == 2: raise OSError("directory sync uncertainty")
            return original(fd)
        with patch("recovery_store.os.fsync", side_effect=fsync):
            self.assertEqual(self.broker().request("start", Peer(501, True)).state, "pending_unavailable")
        self.assertEqual(self.executions, [])
        self.assertEqual(self.broker(store=self.restarted()).request("start", Peer(501, True)).state, "reconciliation_required")

    def test_real_store_other_boot_blocks_recovery_not_explicit_disable(self):
        from recovery_broker import Completion, Peer
        self.store.write(VALUE)
        before = self.path.read_bytes()
        broker = self.broker(store=self.restarted("boot-two"))
        self.assertEqual(broker.request("start", Peer(501, True)).state, "context_unavailable")
        self.assertEqual(broker.disable(), {"state": "off"})
        self.assertEqual(broker.reconcile(Completion(TICKET, 501, True, 0)).state, "pending_unavailable")
        self.assertEqual(self.executions, [])
        self.assertFalse(self.enabled)
        self.assertEqual(self.path.read_bytes(), before)

    def test_missing_read_does_not_create_state(self):
        self.assertIsNone(self.store.read())
        self.assertFalse(self.path.exists())

    def test_pending_and_cleared_state_survive_reconstruction(self):
        self.store.write(VALUE)
        self.assertEqual(self.restarted().read(), VALUE)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.restarted().clear(TICKET, 501)
        self.assertIsNone(self.restarted().read())
        self.assertTrue(self.path.exists())
        self.assert_no_temporaries()

    def test_subprocess_exit_and_fresh_process_read(self):
        code = '''
import json, os, sys
sys.path.insert(0, sys.argv[1])
from recovery_store import PendingCommandStore
store = PendingCommandStore(sys.argv[2], "boot-one", expected_uid=os.getuid())
if sys.argv[3] == "write":
    store.write({"ticket":"a"*32,"uid":501})
    os._exit(0)
print(json.dumps(store.read()))
'''
        base = [sys.executable, "-I", "-c", code, str(Path(__file__).resolve().parents[1] / "src"), str(self.directory)]
        writer = subprocess.run(base + ["write"], capture_output=True, text=True, timeout=5)
        self.assertEqual(writer.returncode, 0, writer.stderr)
        reader = subprocess.run(base + ["read"], capture_output=True, text=True, timeout=5)
        self.assertEqual(reader.returncode, 0, reader.stderr)
        self.assertEqual(json.loads(reader.stdout), VALUE)

    def test_unresolved_other_boot_cannot_be_read_replaced_or_cleared(self):
        self.store.write(VALUE)
        before = self.path.read_bytes()
        other = self.restarted("boot-two")
        for operation in (other.read, lambda: other.write(VALUE), lambda: other.clear(TICKET, 501)):
            with self.assertRaises(ControllerError): operation()
        self.assertEqual(self.path.read_bytes(), before)

    def test_cleared_other_boot_is_not_a_fence_and_read_does_not_rewrite(self):
        self.store.write(VALUE); self.store.clear(TICKET, 501)
        before = self.path.read_bytes()
        other = self.restarted("boot-two")
        self.assertIsNone(other.read())
        self.assertEqual(self.path.read_bytes(), before)
        other.write(VALUE)
        self.assertEqual(json.loads(self.path.read_bytes())["boot_id"], "boot-two")

    def test_unresolved_ticket_cannot_be_overwritten(self):
        self.store.write(VALUE)
        before = self.path.read_bytes()
        for value in ({"ticket": "b"*32, "uid": 501}, {"ticket": TICKET, "uid": 502}):
            with self.assertRaises(ControllerError): self.store.write(value)
        self.assertEqual(self.path.read_bytes(), before)

    def test_same_pending_identity_can_be_durably_rewritten(self):
        self.store.write(VALUE); self.store.write(VALUE)
        self.assertEqual(self.store.read(), VALUE)
        self.assert_no_temporaries()

    def test_only_matching_identity_can_clear(self):
        self.store.write(VALUE)
        for ticket, uid in (("b"*32, 501), (TICKET, 502), (TICKET, True)):
            with self.assertRaises(ControllerError): self.store.clear(ticket, uid)
        self.assertEqual(self.store.read(), VALUE)

    def test_missing_or_already_cleared_identity_cannot_be_cleared_again(self):
        with self.assertRaises(ControllerError): self.store.clear(TICKET, 501)
        self.assertFalse(self.path.exists())
        self.store.write(VALUE); self.store.clear(TICKET, 501)
        with self.assertRaises(ControllerError): self.store.clear(TICKET, 501)

    def test_invalid_values_and_unconditional_clear_are_rejected(self):
        values = (None, True, [], {}, {**VALUE, "command": "anything"},
                  {"ticket": "A"*32, "uid": 501}, {"ticket": "a"*31, "uid": 501},
                  {"ticket": TICKET, "uid": True}, {"ticket": TICKET, "uid": 0},
                  {"ticket": TICKET, "uid": -1}, {"ticket": TICKET, "uid": MAX_UID+1})
        for value in values:
            with self.subTest(value=value), self.assertRaises(ControllerError): self.store.write(value)
        self.assertFalse(self.path.exists())

    def test_invalid_boot_and_owner_configuration(self):
        for boot in (None, True, "", "../boot", "x"*129):
            with self.assertRaises(ControllerError): PendingCommandStore(self.directory, boot)
        for uid in (True, -1, MAX_UID+1):
            with self.assertRaises(ControllerError): PendingCommandStore(self.directory, "boot-one", uid)

    def test_wrong_directory_owner_and_modes_are_rejected(self):
        other = PendingCommandStore(self.directory, "boot-one", expected_uid=os.getuid()+1)
        with self.assertRaises(ControllerError): other.read()
        self.directory.chmod(0o755)
        with self.assertRaises(ControllerError): self.store.read()
        with self.assertRaises(ControllerError): self.store.write(VALUE)

    def test_symlink_directory_is_rejected(self):
        alias = self.root / "alias"; alias.symlink_to(self.directory, target_is_directory=True)
        store = PendingCommandStore(alias, "boot-one", expected_uid=os.getuid())
        with self.assertRaises(OSError): store.read()
        with self.assertRaises(OSError): store.write(VALUE)

    def test_missing_directory_is_not_silently_created(self):
        store = PendingCommandStore(self.root / "missing", "boot-one", expected_uid=os.getuid())
        with self.assertRaises(FileNotFoundError): store.write(VALUE)
        self.assertFalse((self.root / "missing").exists())

    def test_symlink_file_is_not_followed_or_overwritten(self):
        outside = self.root / "outside"; outside.write_text("private other data")
        self.path.symlink_to(outside)
        for operation in (self.store.read, lambda: self.store.write(VALUE), lambda: self.store.clear(TICKET, 501)):
            with self.assertRaises(OSError): operation()
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(outside.read_text(), "private other data")

    def test_hardlink_is_rejected(self):
        self.store.write(VALUE)
        os.link(self.path, self.root / "alias")
        with self.assertRaises(ControllerError): self.store.read()
        with self.assertRaises(ControllerError): self.store.clear(TICKET, 501)

    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(ControllerError): self.store.read()
        with self.assertRaises(ControllerError): self.store.write(VALUE)

    def test_wrong_file_mode_is_rejected(self):
        self.store.write(VALUE); self.path.chmod(0o644)
        with self.assertRaises(ControllerError): self.store.read()
        with self.assertRaises(ControllerError): self.store.write(VALUE)

    def test_schema_corruption_and_duplicates_are_rejected(self):
        record = {"version": 1, "boot_id": "boot-one", "pending": VALUE}
        bad = ["private provider data", "[]", json.dumps({**record, "version": True}),
               json.dumps({**record, "extra": "secret"}), json.dumps({**record, "boot_id": []}),
               '{"version":1,"boot_id":"boot-one","pending":null,"pending":null}',
               '{"version":1,"boot_id":"boot-one","pending":{"ticket":"'+TICKET+'","uid":501,"uid":502}}']
        for raw in bad:
            self.write_raw(raw)
            with self.assertRaises(ControllerError) as error: self.store.read()
            self.assertNotIn("private provider", str(error.exception))
            before = self.path.read_bytes()
            with self.assertRaises(ControllerError): self.store.write(VALUE)
            self.assertEqual(self.path.read_bytes(), before)

    def test_oversized_and_invalid_utf8_are_rejected(self):
        for raw in (b" "*(MAX_BYTES+1), b"\xff"):
            self.write_raw(raw)
            with self.assertRaises(ControllerError): self.store.read()

    def test_restrictive_umask_still_produces_exact_private_mode(self):
        previous = os.umask(0o777)
        try: self.store.write(VALUE)
        finally: os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_failed_replace_preserves_pending_and_cleans_temporary(self):
        self.store.write(VALUE)
        before = self.path.read_bytes()
        with patch("recovery_store.os.replace", side_effect=OSError("interruption")):
            with self.assertRaises(OSError): self.store.clear(TICKET, 501)
        self.assertEqual(self.path.read_bytes(), before)
        self.assert_no_temporaries()

    def test_file_fsync_failure_does_not_clear_pending(self):
        self.store.write(VALUE)
        with patch("recovery_store.os.fsync", side_effect=OSError("write failure")):
            with self.assertRaises(OSError): self.store.clear(TICKET, 501)
        self.assertEqual(self.store.read(), VALUE)
        self.assert_no_temporaries()

    def test_directory_fsync_failure_after_replace_is_not_assumed_rolled_back(self):
        original = os.fsync
        count = 0
        def fsync(fd):
            nonlocal count
            count += 1
            if count == 2: raise OSError("directory sync failed")
            return original(fd)
        with patch("recovery_store.os.fsync", side_effect=fsync):
            with self.assertRaises(OSError): self.store.write(VALUE)
        self.assertEqual(self.restarted().read(), VALUE)
        self.assert_no_temporaries()

    def test_temporary_name_collision_does_not_delete_existing_file(self):
        existing = self.directory / (".recovery-pending-" + "c"*32)
        existing.write_text("unrelated file")
        with patch("recovery_store.uuid.uuid4", return_value=SimpleNamespace(hex="c"*32)):
            with self.assertRaises(FileExistsError): self.store.write(VALUE)
        self.assertEqual(existing.read_text(), "unrelated file")
        self.assertFalse(self.path.exists())

    def test_directory_fd_anchors_clear_across_path_replacement(self):
        self.store.write(VALUE)
        moved = self.root / "old-state"
        original = self.store._directory
        def swap():
            fd = original()
            self.directory.rename(moved)
            self.directory.mkdir(mode=0o700)
            (self.directory / "unrelated").write_text("leave alone")
            return fd
        with patch.object(self.store, "_directory", side_effect=swap): self.store.clear(TICKET, 501)
        self.assertFalse(self.path.exists())
        self.assertIsNone(PendingCommandStore(moved, "boot-one", expected_uid=os.getuid()).read())
        self.assertEqual((self.directory / "unrelated").read_text(), "leave alone")


if __name__ == "__main__": unittest.main()
