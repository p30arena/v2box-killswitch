import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from audit import AuditJournal
from coordinator import Coordinator
import test_runtime


class RuntimeAuditTests(unittest.TestCase):
    def setUp(self):
        test_runtime.RuntimeTests.setUp(self)
        self.journal = AuditJournal(self.temp.name, owner_uid=os.geteuid(), now=lambda: 1000)
        self.runtime.audit = self.journal

    def events(self): return self.journal.read()["events"]

    def fail_discovery(self):
        def failing(args): raise RuntimeError("secret endpoint.example password=hidden")
        self.runtime.runner = failing

    def test_discovery_failure_records_stage_and_quarantine_without_secrets(self):
        self.runtime.dispatch("enable")
        self.fail_discovery()
        with self.assertRaises(RuntimeError): self.runtime.dispatch("refresh")
        data = self.journal.read()
        self.assertEqual(data["last_failure"]["stage"], "discover_interfaces")
        self.assertEqual(data["events"][-1]["outcome"], "quarantined")
        self.assertIn("v2box_default_deny", self.native.pf.rules)
        self.assertNotIn("on utun3", self.native.pf.rules)
        self.assertNotIn("password", self.journal.path.read_text())
        self.assertNotIn("endpoint.example", self.journal.path.read_text())

    def test_logging_failure_cannot_prevent_quarantine(self):
        self.runtime.dispatch("enable")
        self.fail_discovery()
        with patch.object(self.journal, "record", side_effect=OSError("full disk")):
            with self.assertRaises(RuntimeError): self.runtime.dispatch("refresh")
        self.assertIn("v2box_default_deny", self.native.pf.rules)
        self.assertNotIn("on utun3", self.native.pf.rules)

    def test_quarantine_failure_is_not_reported_as_success(self):
        self.runtime.dispatch("enable")
        self.fail_discovery()
        with patch.object(self.controller, "quarantine", side_effect=RuntimeError("private error")):
            with self.assertRaises(RuntimeError): self.runtime.dispatch("refresh")
        last = self.events()[-1]
        self.assertEqual((last["stage"], last["outcome"]), ("fallback_quarantine", "failed"))

    def test_unapproved_profile_has_separate_approval_record(self):
        self.runtime.dispatch("enable")
        self.config["profile"] = "private unknown profile"
        self.runtime.dispatch("refresh")
        last = self.journal.read()["last_failure"]
        self.assertEqual((last["stage"], last["reason"]), ("validate_approval", "approval_required"))
        self.assertEqual(self.events()[-1]["stage"], "approval_quarantine")
        self.assertNotIn("private unknown", self.journal.path.read_text())

    def test_refresh_records_tunnel_absence_without_claiming_health(self):
        self.runtime.dispatch("enable")
        self.native.status = "Disconnected"
        result = self.runtime.dispatch("refresh")
        self.assertEqual(self.events()[-1]["reason"], "tunnel_absent")
        self.assertEqual(result["vpn_health"], "unverified")
        self.assertNotIn("on utun3", self.native.pf.rules)

    def test_disable_survives_logging_failure(self):
        self.runtime.dispatch("enable")
        with patch.object(self.journal, "record", side_effect=OSError("full disk")):
            result = self.runtime.dispatch("disable")
        self.assertEqual(result["state"], "off")
        self.assertEqual(result["diagnostic_recording"], "unavailable")
        self.assertFalse(self.controller.store.read())
        self.assertEqual(self.native.pf.rules, "")

    def test_disable_enforcement_failure_is_logged_not_called_off(self):
        self.runtime.dispatch("enable")
        with patch.object(self.controller.backend, "remove", side_effect=RuntimeError("secret")):
            with self.assertRaises(RuntimeError): self.runtime.dispatch("disable")
        self.assertEqual(self.events()[-1]["outcome"], "failed")
        self.assertFalse(self.controller.store.read())

    def test_off_refresh_and_status_do_not_write_journal(self):
        self.runtime.dispatch("enable")
        self.runtime.dispatch("disable")
        before = self.journal.path.read_bytes()
        self.runtime.dispatch("refresh")
        self.runtime.dispatch("status")
        self.assertEqual(self.journal.path.read_bytes(), before)
        self.assertEqual(self.native.pf.rules, "")

    def test_preflight_failure_stage_is_recorded_without_state_change(self):
        self.native.skip = "en0 (skip)"
        with self.assertRaises(Exception): self.runtime.dispatch("enable")
        self.assertEqual(self.journal.read()["last_failure"]["stage"], "check_skip")
        self.assertFalse(self.controller.store.read())
        self.assertEqual(self.native.pf.rules, "")

    def test_coordinator_callback_failure_cannot_prevent_approval_quarantine(self):
        self.runtime.dispatch("enable")
        def broken_callback(*args): raise OSError("diagnostics unavailable")
        result = Coordinator(self.controller, audit=broken_callback).update(
            self.runtime.snapshot(self.config), self.config["inventory"], "unknown", 1000)
        self.assertEqual(result["state"], "on")
        self.assertNotIn("on utun3", self.native.pf.rules)
        self.assertIn("v2box_default_deny", self.native.pf.rules)

    def test_untrusted_history_is_unavailable_not_copied_to_status(self):
        self.runtime.dispatch("enable")
        self.journal.path.chmod(0o644)
        result = self.runtime.dispatch("status")
        self.assertEqual(result["diagnostic_history"], "unavailable")
        self.assertNotIn("last_failure_stage", result)

    def test_status_exposes_only_small_allowlisted_failure_summary(self):
        self.runtime.dispatch("enable")
        self.fail_discovery()
        with self.assertRaises(RuntimeError): self.runtime.dispatch("refresh")
        result = self.runtime.dispatch("status")
        self.assertEqual(result["last_failure_stage"], "discover_interfaces")
        self.assertEqual(result["diagnostic_history"], "available")
        self.assertTrue(all(isinstance(value, str) for value in result.values()))
        self.assertNotIn("events", result)


if __name__ == "__main__": unittest.main()
