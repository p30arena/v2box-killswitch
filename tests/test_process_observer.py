from dataclasses import replace
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from controller import ControllerError
from process_observer import KernelProcessObserver, ProcessSnapshot

WORKER = ProcessSnapshot(101, 100, 501, 501, 501, 20, 20, 20, 1000, 10, 3)
CHILD = ProcessSnapshot(102, 101, 501, 501, 501, 20, 20, 20, 1001, 20, 4)


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.values = {101: WORKER, 102: CHILD}
        self.calls = []
        def read(pid):
            self.calls.append(pid)
            return self.values[pid]
        self.observer = KernelProcessObserver(read)

    def verify(self, **overrides):
        args = dict(worker=WORKER.identity(), child=CHILD.identity(), uid=501,
                    primary_gid=20, worker_parent_pid=100)
        args.update(overrides)
        return self.observer.verify_staged(**args)

    def test_observes_kernel_data_and_brackets_staged_child(self):
        self.assertEqual(self.verify(), {"worker": WORKER.identity(), "child": CHILD.identity()})
        self.assertEqual(self.calls, [101, 101, 102, 102, 101, 101, 102, 102])

    def test_bad_pids_are_rejected_without_lookup(self):
        for pid in (0, -1, True, "101", 1 << 31):
            with self.assertRaises(ControllerError): self.observer.observe(pid)
        self.assertEqual(self.calls, [])

    def test_missing_or_denied_is_unknown_not_completion(self):
        for error in (ProcessLookupError("private process"), PermissionError("private account")):
            def read(pid): raise error
            observer = KernelProcessObserver(read)
            with self.assertRaises(ControllerError) as caught: observer.observe(101)
            self.assertNotIn("private", str(caught.exception))

    def test_wrong_pid_or_untyped_kernel_response_rejected(self):
        for value in (replace(WORKER, pid=999), None, {"pid": 101}):
            with self.assertRaises(ControllerError): KernelProcessObserver(lambda pid: value).observe(101)

    def test_pid_reuse_or_credentials_changed_between_reads_rejected(self):
        for update in ({"birth_microseconds": 11}, {"parent_pid": 99}, {"saved_uid": 0}, {"gid": 0}):
            samples = [WORKER, replace(WORKER, **update)]
            with self.assertRaises(ControllerError): KernelProcessObserver(lambda pid: samples.pop(0)).observe(101)

    def test_birth_claims_must_match_independent_kernel_snapshot(self):
        for field in ("worker", "child"):
            identity = dict(WORKER.identity() if field == "worker" else CHILD.identity())
            identity["birth_seconds"] += 1
            with self.assertRaises(ControllerError): self.verify(**{field: identity})

    def test_parent_relationships_are_not_worker_claims(self):
        self.values[102] = replace(CHILD, parent_pid=999)
        with self.assertRaises(ControllerError): self.verify()
        self.values[102] = CHILD
        with self.assertRaises(ControllerError): self.verify(worker_parent_pid=99)

    def test_real_effective_and_saved_credentials_must_all_match(self):
        for pid in (101, 102):
            for field in ("uid", "real_uid", "saved_uid", "gid", "real_gid", "saved_gid"):
                self.values = {101: WORKER, 102: CHILD}
                self.values[pid] = replace(self.values[pid], **{field: 0})
                with self.assertRaises(ControllerError): self.verify()

    def test_child_must_be_stopped_at_every_observation(self):
        for state in (1, 2, 3, 5):
            self.values[102] = replace(CHILD, state=state)
            with self.assertRaises(ControllerError): self.verify()

    def test_stopped_or_zombie_worker_is_not_active_supervisor(self):
        for state in (1, 4, 5):
            self.values[101] = replace(WORKER, state=state)
            with self.assertRaises(ControllerError): self.verify()

    def test_running_sleeping_worker_transitions_are_not_identity_changes(self):
        count = 0
        def read(pid):
            nonlocal count
            count += 1
            return replace(WORKER, state=2 if count % 2 else 3) if pid == 101 else CHILD
        self.observer = KernelProcessObserver(read)
        self.assertEqual(self.verify()["worker"], WORKER.identity())

    def test_late_child_or_worker_change_rejected(self):
        for changed_pid in (101, 102):
            count = {101: 0, 102: 0}
            def read(pid):
                count[pid] += 1
                original = WORKER if pid == 101 else CHILD
                return replace(original, birth_seconds=2000) if pid == changed_pid and count[pid] >= 3 else original
            self.observer = KernelProcessObserver(read)
            with self.assertRaises(ControllerError): self.verify()

    def test_unsupported_platform_is_not_fake_observation(self):
        with patch("process_observer.sys.platform", "unsupported"):
            with self.assertRaises(ControllerError): KernelProcessObserver()

    def test_native_loader_failure_is_sanitized(self):
        with patch("process_observer.sys.platform", "darwin"), patch(
                "process_observer.ctypes.CDLL", side_effect=OSError("private library detail")):
            with self.assertRaises(ControllerError) as error: KernelProcessObserver()
            self.assertNotIn("private", str(error.exception))

    def test_short_failed_or_missing_native_read_is_unknown(self):
        for result in (0, -1, 135):
            class Query:
                def __call__(self, *args): return result
            with patch("process_observer.sys.platform", "darwin"), patch(
                    "process_observer.ctypes.CDLL", return_value=SimpleNamespace(proc_pidinfo=Query())):
                observer = KernelProcessObserver()
                with self.assertRaises(ControllerError): observer.observe(101)

    def test_invalid_expectations_and_snapshot_fields_rejected(self):
        for override in ({"uid": 0}, {"uid": True}, {"primary_gid": True},
                         {"worker_parent_pid": 0}, {"child": WORKER.identity()}):
            with self.assertRaises(ControllerError): self.verify(**override)
        for override in ({"uid": True}, {"parent_pid": -1}, {"birth_microseconds": 1_000_000}, {"state": 9}):
            invalid = replace(WORKER, **override)
            with self.assertRaises(ControllerError): KernelProcessObserver(lambda pid: invalid).observe(101)


if __name__ == "__main__": unittest.main()
