import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from controller import StateStore
from endpoints import approved_config
from policy import compile_policy
import test_trial

spec = importlib.util.spec_from_file_location("trial_observer_test", Path(__file__).resolve().parents[1] / "tools/observe_first_test.py")
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


class ConfirmationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.test = self.base / "first-test"; self.test.mkdir()
        (self.base / "state").mkdir()
        (self.base / "state/runtime.lock").touch()
        self.store = StateStore(self.base / "state")
        with self.store.locked(): self.store.write(True)
        self.snapshot = {"physical": ["en0"], "tunnel": "utun3", "gateways": []}
        self.config = {"profile": "one", "inventory": {"version": 1, "profiles": {"one": {
            "revision": "1", "expires_at": 2000,
            "endpoints": [{"address": "1.0.0.1", "port": 443, "protocol": "tcp"}]}}}}
        fixture = test_trial.TrialTests(); fixture.setUp()
        self.report = copy.deepcopy(fixture.report)
        self.report["verdict"] = "review_required"
        expected = compile_policy(approved_config(self.snapshot, self.config["inventory"], "one", 1000))
        self.kernel_rules = expected
        self.gate = True
        self.pf_enabled = True
        self.preflight_ok = True
        self.calls = []
        outer = self

        class Runtime:
            def __init__(self, *a, **k): pass
            def snapshot(self, config): return outer.snapshot
            def preflight(self):
                if not outer.preflight_ok: raise RuntimeError("preflight refused")

        class Backend:
            def __init__(self, *a, **k): pass
            def _root_has_gate(self): return outer.gate
            def _call(self, *args, text=None):
                outer.calls.append(args)
                if args == ("-s", "info"): return "Status: Enabled" if outer.pf_enabled else "Status: Disabled"
                if args[:2] == ("-n", "-v"): return text
                if args[-1] == "-sr": return outer.kernel_rules
                raise AssertionError("unexpected command")

        for target, value in [("runtime.Runtime", Runtime), ("runtime.read_config", lambda _: self.config),
                              ("pf_driver.PFDriver", Backend)]:
            p = patch(target, value); p.start(); self.addCleanup(p.stop)
        for attribute, value in [("BASE", self.base), ("TEST", self.test)]:
            p = patch.object(observer, attribute, value); p.start(); self.addCleanup(p.stop)
        p = patch.object(observer.time, "time", return_value=1000); p.start(); self.addCleanup(p.stop)

    def confirm(self):
        return observer.confirm_limited_trial(self.config, self.snapshot, self.report)

    def test_confirm_limited_pass_without_mutating_pf(self):
        self.assertTrue(self.confirm())
        self.assertTrue((self.test / "confirmed").exists())
        self.assertEqual(json.loads((self.test / "confirmed").read_text())["scope"], "limited_ipv4_only")
        self.assertFalse(any("-E" in call or "-X" in call for call in self.calls))
        self.assertTrue(all("-f" not in call or "-n" in call for call in self.calls))

    def test_counter_reset_does_not_confirm(self):
        self.report["block_counter_after"] = 0
        self.assertFalse(self.confirm())
        self.assertFalse((self.test / "confirmed").exists())

    def test_disable_wins_over_confirmation(self):
        with self.store.locked(): self.store.write(False)
        self.assertFalse(self.confirm())
        self.assertFalse(self.store.read())
        self.assertFalse((self.test / "confirmed").exists())

    def test_quarantine_wins_over_confirmation(self):
        (self.test / "fallback-applied").touch()
        self.assertFalse(self.confirm())
        self.assertFalse((self.test / "confirmed").exists())

    def test_changed_kernel_cannot_confirm(self):
        self.kernel_rules = "pass out all"
        self.assertFalse(self.confirm())
        self.assertFalse((self.test / "confirmed").exists())

    def test_disabled_pf_cannot_confirm(self):
        self.pf_enabled = False
        self.assertFalse(self.confirm())

    def test_gate_missing_cannot_confirm(self):
        self.gate = False
        self.assertFalse(self.confirm())


if __name__ == "__main__": unittest.main()
