import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from audit import AuditJournal, MAX_BYTES, MAX_EVENTS


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.journal = AuditJournal(self.directory, owner_uid=os.geteuid(), now=lambda: 1234)

    def record(self, **kwargs):
        self.journal.record(kwargs.get("operation", "refresh"), kwargs.get("stage", "discover_gateways"),
                            kwargs.get("outcome", "failed"), kwargs.get("reason", "operation_failed"))

    def test_missing_journal_read_has_no_side_effects(self):
        self.assertEqual(self.journal.read()["events"], [])
        self.assertFalse(self.journal.path.exists())

    def test_private_mode_and_metadata_only(self):
        self.record()
        self.assertEqual(self.journal.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.journal.read()["last_failure"]["stage"], "discover_gateways")

    def test_unknown_metadata_is_rejected_without_writing(self):
        for field in ("operation", "stage", "outcome", "reason"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.record(**{field: "secret-server.example password=hidden"})
        self.assertFalse(self.journal.path.exists())

    def test_duplicate_events_coalesce(self):
        for _ in range(10): self.record()
        events = self.journal.read()["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["count"], 10)

    def test_bounded_history_retains_last_failure_after_recovery(self):
        self.record()
        for i in range(MAX_EVENTS + 20):
            self.record(stage="refresh_enforcement", outcome="started" if i % 2 else "ok", reason="tunnel_present")
        data = self.journal.read()
        self.assertEqual(len(data["events"]), MAX_EVENTS)
        self.assertLess(self.journal.path.stat().st_size, MAX_BYTES)
        self.assertEqual(data["last_failure"]["stage"], "discover_gateways")
        self.assertGreater(data["events"][0]["sequence"], 1)

    def test_successful_quarantine_does_not_erase_failure_cause(self):
        self.record()
        self.record(stage="fallback_quarantine", outcome="quarantined", reason="runtime_failure")
        self.assertEqual(self.journal.read()["last_failure"]["stage"], "discover_gateways")

    def test_interrupted_replace_preserves_previous_history(self):
        self.record()
        before = self.journal.path.read_bytes()
        with patch("audit.os.replace", side_effect=OSError("disk failure")), self.assertRaises(OSError):
            self.record(stage="refresh_enforcement")
        self.assertEqual(self.journal.path.read_bytes(), before)
        self.assertEqual(list(self.directory.glob(".diagnostics-*")), [])

    def test_symlink_file_rejected(self):
        target = self.directory / "other"
        target.write_text("do not touch")
        self.journal.path.symlink_to(target)
        with self.assertRaises(OSError): self.record()
        self.assertEqual(target.read_text(), "do not touch")

    def test_hardlink_rejected(self):
        self.record()
        os.link(self.journal.path, self.directory / "other")
        with self.assertRaises(ValueError): self.record()

    def test_wrong_permissions_and_owner_rejected(self):
        self.record()
        self.journal.path.chmod(0o644)
        with self.assertRaises(ValueError): self.journal.read()
        with self.assertRaises(ValueError): AuditJournal(self.directory, owner_uid=os.geteuid()+1).read()

    def test_untrusted_directory_rejected(self):
        self.directory.chmod(0o755)
        try:
            with self.assertRaises(ValueError): self.record()
        finally: self.directory.chmod(0o700)

    def test_fifo_rejected_without_blocking(self):
        os.mkfifo(self.journal.path, 0o600)
        with self.assertRaises(ValueError): self.journal.read()

    def test_malformed_and_oversized_records_rejected(self):
        for raw in (b"{", b"x" * (MAX_BYTES + 1), b'{"version":true,"events":[],"last_failure":null}'):
            self.journal.path.write_bytes(raw); self.journal.path.chmod(0o600)
            with self.assertRaises(ValueError): self.journal.read()

    def test_unexpected_fields_are_not_copied_forward(self):
        self.record()
        data = self.journal.read(); data["events"][0]["server"] = "do not retain"
        self.journal.path.write_text(json.dumps(data))
        with self.assertRaises(ValueError): self.record()

    def test_nonfinite_clock_rejected(self):
        self.journal.now = lambda: float("nan")
        with self.assertRaises(ValueError): self.record()
        self.assertFalse(self.journal.path.exists())


if __name__ == "__main__": unittest.main()
