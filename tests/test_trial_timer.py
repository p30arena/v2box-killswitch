import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from audit import AuditJournal
from controller import StateStore

spec = importlib.util.spec_from_file_location("trial_timer_test", Path(__file__).resolve().parents[1] / "tools/first_test_fallback.py")
timer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timer)
prep_spec = importlib.util.spec_from_file_location("trial_prepare_test", Path(__file__).resolve().parents[1] / "tools/prepare_first_test.py")
preparer = importlib.util.module_from_spec(prep_spec)
prep_spec.loader.exec_module(preparer)


class Clock:
    def __init__(self): self.now = 0; self.hook = None
    def monotonic(self): return self.now
    def time(self): return 1700000000 + self.now
    def sleep(self, seconds):
        self.now += seconds
        if self.hook: self.hook(self.now)


class TrialTimerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.test = self.base / "first-test"; self.test.mkdir(mode=0o700)
        self.state = self.base / "state"; self.state.mkdir(mode=0o700)
        self.store = StateStore(self.state)
        self.set_intent(True)
        self.clock = Clock()
        self.journal = AuditJournal(self.state, owner_uid=os.geteuid(), now=self.clock.time)
        self.applied = False
        self.fail_command = None
        self.calls = []
        def run(args, **kwargs):
            self.calls.append(args)
            self.assertEqual(args[0], "/sbin/pfctl")
            self.assertEqual(args[args.index("-a")+1], "com.p30arena.v2box-killswitch")
            self.assertEqual(args[-1], str(self.test / "quarantine.pf"))
            self.assertFalse({"-d", "-E", "-X", "-F"}.intersection(args))
            syntax = "-n" in args
            if self.fail_command == ("syntax" if syntax else "apply"):
                raise subprocess.CalledProcessError(1, args, output="secret endpoint", stderr="password=hidden")
            if not syntax: self.applied = True
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        for p in (patch.object(timer, "BASE", self.base), patch.object(timer, "TEST", self.test),
                  patch.object(timer, "time", self.clock), patch.object(timer.os, "geteuid", return_value=0),
                  patch.object(timer.subprocess, "run", side_effect=run),
                  patch.object(timer.sys, "argv", ["timer", "--watch"]),
                  patch.object(timer.sys, "path", sys.path.copy()),
                  patch("audit.AuditJournal", return_value=self.journal)):
            p.start(); self.addCleanup(p.stop)

    def set_intent(self, enabled):
        with self.store.locked(): self.store.write(enabled)

    def last(self): return self.journal.read()["events"][-1]

    def check_preflight(self, **changes):
        reply = {"state": "off", "diagnostic_history": "available",
                 "diagnostic_capability": "backend_and_trial_timer_v1"}
        reply.update(changes)
        with patch.object(preparer, "BASE", self.base), patch.object(preparer, "command",
                return_value=SimpleNamespace(stdout=json.dumps(reply))) as command:
            preparer.check_diagnostics()
            command.assert_called_once_with(["/Library/PrivilegedHelperTools/org.v2boxkillswitch.backend", "status"])

    def test_preflight_requires_actual_diagnostic_write(self):
        self.set_intent(False)
        self.check_preflight()
        self.assertEqual(self.last()["stage"], "diagnostic_preflight")
        self.assertEqual(self.calls, [])
        self.assertFalse(self.store.read())

    def test_preflight_rejects_old_or_unreadable_backend(self):
        self.set_intent(False)
        for changes in ({"diagnostic_capability": None}, {"diagnostic_history": "unavailable"}, {"state": "on"}):
            with self.assertRaises(RuntimeError): self.check_preflight(**changes)
        self.assertFalse(self.journal.path.exists())
        self.assertEqual(self.calls, [])

    def test_preflight_write_failure_stops_preparation(self):
        self.set_intent(False)
        with patch.object(self.journal, "record", side_effect=OSError("cannot record")):
            with self.assertRaises(OSError): self.check_preflight()
        self.assertFalse(self.journal.path.exists())
        self.assertEqual(self.calls, [])

    def test_preflight_rechecks_off_intent_under_lock(self):
        with self.assertRaises(RuntimeError): self.check_preflight()
        self.assertFalse(self.journal.path.exists())
        self.assertTrue(self.store.read())
        self.assertEqual(self.calls, [])

    def test_unconfirmed_deadline_records_every_mutation_phase(self):
        self.assertEqual(timer.main(), 0)
        self.assertEqual(self.clock.now, 600)
        self.assertTrue(self.applied)
        self.assertFalse(self.store.read())
        self.assertTrue((self.test / "fallback-applied").exists())
        completed = {e["stage"] for e in self.journal.read()["events"] if e["outcome"] == "ok"}
        self.assertTrue({"trial_syntax", "trial_disable_intent", "trial_apply_quarantine", "trial_marker"}.issubset(completed))
        self.assertIsNone(self.journal.read()["last_failure"])

    def test_confirmation_never_changes_rules_or_intent(self):
        (self.test / "confirmed").write_text("limited IPv4")
        self.assertEqual(timer.main(), 0)
        self.assertEqual(self.calls, [])
        self.assertTrue(self.store.read())
        self.assertEqual(self.last()["reason"], "confirmation_present")

    def test_confirmation_during_wait_wins(self):
        self.clock.hook = lambda now: (self.test / "confirmed").touch() if now == 3 else None
        self.assertEqual(timer.main(), 0)
        self.assertEqual(self.calls, [])
        self.assertTrue(self.store.read())

    def test_no_activation_exits_without_pf_or_intent_changes(self):
        self.set_intent(False)
        self.assertEqual(timer.main(), 0)
        self.assertEqual(self.clock.now, 900)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.store.read())
        self.assertEqual(self.last()["reason"], "activation_timeout")

    def test_disable_during_wait_wins(self):
        self.clock.hook = lambda now: self.set_intent(False) if now == 3 else None
        self.assertEqual(timer.main(), 0)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.last()["reason"], "disabled_intent")

    def test_disable_at_deadline_wins(self):
        self.clock.hook = lambda now: self.set_intent(False) if now == 600 else None
        self.assertEqual(timer.main(), 0)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.last()["outcome"], "skipped_disabled")

    def test_confirmation_at_deadline_wins(self):
        self.clock.hook = lambda now: (self.test / "confirmed").touch() if now == 600 else None
        self.assertEqual(timer.main(), 0)
        self.assertEqual(self.calls, [])
        self.assertTrue(self.store.read())
        self.assertEqual(self.last()["stage"], "trial_deadline")

    def test_syntax_failure_is_recorded_and_does_not_disable_intent(self):
        self.fail_command = "syntax"
        with self.assertRaises(subprocess.CalledProcessError): timer.main()
        self.assertFalse(self.applied)
        self.assertTrue(self.store.read())
        self.assertEqual(self.last()["stage"], "trial_syntax")
        self.assertEqual(self.last()["outcome"], "failed")
        self.assertNotIn("password", self.journal.path.read_text())
        self.assertNotIn("secret endpoint", self.journal.path.read_text())

    def test_apply_failure_never_writes_success_marker(self):
        self.fail_command = "apply"
        with self.assertRaises(subprocess.CalledProcessError): timer.main()
        self.assertFalse(self.applied)
        self.assertFalse(self.store.read())
        self.assertFalse((self.test / "fallback-applied").exists())
        self.assertEqual(self.last()["stage"], "trial_apply_quarantine")
        self.assertEqual(self.last()["outcome"], "failed")

    def test_missing_marker_does_not_prove_no_quarantine(self):
        original = Path.write_text
        def write(path, *args, **kwargs):
            if path.name == "fallback-applied": raise OSError("marker write failed")
            return original(path, *args, **kwargs)
        with patch.object(Path, "write_text", write):
            with self.assertRaises(OSError): timer.main()
        self.assertTrue(self.applied)
        self.assertFalse((self.test / "fallback-applied").exists())
        self.assertEqual(self.last()["stage"], "trial_marker")
        self.assertEqual(self.last()["outcome"], "failed")
        self.assertTrue(any(e["stage"] == "trial_apply_quarantine" and e["outcome"] == "ok"
                            for e in self.journal.read()["events"]))

    def test_audit_failure_does_not_prevent_quarantine(self):
        with patch.object(self.journal, "record", side_effect=OSError("diagnostic disk failure")):
            self.assertEqual(timer.main(), 0)
        self.assertTrue(self.applied)
        self.assertTrue((self.test / "fallback-applied").exists())


if __name__ == "__main__": unittest.main()
