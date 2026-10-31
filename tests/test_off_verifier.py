import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("off_verifier_test", Path(__file__).resolve().parents[1] / "tools/verify_diagnostics_off.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class OffVerifierTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        (self.base / "state").mkdir()
        (self.base / "state/intent.json").write_text(json.dumps({"version": 1, "enabled": False}))
        self.info = "Status: Disabled"
        self.rules = ""
        self.timer_loaded = False
        def run(args):
            self.assertEqual(args[0], "/sbin/pfctl")
            self.assertTrue(args[-1] in {"info", "-sr"})
            return SimpleNamespace(stdout=self.info if args[-1] == "info" else self.rules)
        def timer(args, **kwargs):
            self.assertEqual(args, ["/bin/launchctl", "print", "system/org.v2boxkillswitch.firsttest"])
            return SimpleNamespace(returncode=0 if self.timer_loaded else 1, stderr="Could not find service")
        for p in (patch.object(verifier, "BASE", self.base), patch.object(verifier, "TIMER_PLIST", self.base / "timer.plist"),
                  patch.object(verifier, "run", side_effect=run), patch.object(verifier.subprocess, "run", side_effect=timer)):
            p.start(); self.addCleanup(p.stop)

    def test_off_baseline_only_reads_pf_and_launchctl(self):
        verifier.verify_off()

    def test_enabled_intent_refuses_verification(self):
        (self.base / "state/intent.json").write_text(json.dumps({"version": 1, "enabled": True}))
        with self.assertRaises(RuntimeError): verifier.verify_off()

    def test_approved_inventory_refuses_verification(self):
        (self.base / "approved.json").write_text("{}")
        with self.assertRaises(RuntimeError): verifier.verify_off()

    def test_enabled_pf_refuses_verification(self):
        self.info = "Status: Enabled"
        with self.assertRaises(RuntimeError): verifier.verify_off()

    def test_nonempty_anchor_refuses_verification(self):
        self.rules = "block drop out all"
        with self.assertRaises(RuntimeError): verifier.verify_off()

    def test_loaded_timer_refuses_verification(self):
        self.timer_loaded = True
        with self.assertRaises(RuntimeError): verifier.verify_off()

    def test_timer_startup_file_refuses_verification(self):
        (self.base / "timer.plist").touch()
        with self.assertRaises(RuntimeError): verifier.verify_off()


if __name__ == "__main__": unittest.main()
