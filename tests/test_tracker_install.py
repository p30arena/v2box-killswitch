"""Installer fixtures only: temporary home, mocked launchctl/signature/UID. No installation."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("tracker_install", Path(__file__).resolve().parents[1] / "tools/install_tracker_user.py")
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class TrackerInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.home = base / "home"
        self.home.mkdir()
        self.repo = base / "repo"
        app = self.repo / ".build/V2Box Reconnect Tracker.app/Contents"
        app.mkdir(parents=True)
        (app / "MacOS").mkdir()
        (app / "MacOS/V2BoxReconnectTracker").write_text("fixture, not executable")
        with (app / "Info.plist").open("wb") as f:
            plistlib.dump({"CFBundleIdentifier": installer.LABEL}, f)
        self.calls = []
        self.agent = self.home / "Library/LaunchAgents" / (installer.LABEL + ".plist")
        self.old = self.agent.parent / "com.ali.v2box-vpn-guard.plist"

    def run_command(self, *args, **kwargs):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 1 if args[0] == "/usr/bin/pgrep" else 0, "", "")

    def invoke(self, *arguments, uid=502):
        with patch.object(installer, "REPO", self.repo), patch.object(Path, "home", return_value=self.home), \
             patch.object(os, "getuid", return_value=uid), patch.object(os, "geteuid", return_value=uid), \
             patch.object(installer, "run", side_effect=self.run_command), \
             patch.object(sys, "argv", ["install_tracker_user.py", *arguments]), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            installer.main()

    def test_explicit_install_flag_required(self):
        with self.assertRaises(SystemExit): self.invoke()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.agent.exists())

    def test_root_refused_before_any_command(self):
        with self.assertRaises(SystemExit): self.invoke("--install-start-at-login", uid=0)
        self.assertEqual(self.calls, [])

    def test_startup_fixture_is_user_only_automatic_and_crash_restart(self):
        self.invoke("--install-start-at-login")
        with self.agent.open("rb") as f: configuration = plistlib.load(f)
        self.assertTrue(configuration["RunAtLoad"])
        self.assertEqual(configuration["KeepAlive"], {"SuccessfulExit": False})
        self.assertEqual(configuration["LimitLoadToSessionType"], "Aqua")
        self.assertEqual(configuration["ProgramArguments"], [str(self.home / "Applications/V2Box Reconnect Tracker.app/Contents/MacOS/V2BoxReconnectTracker")])
        self.assertIn(("/bin/launchctl", "bootstrap", "gui/502", str(self.agent)), self.calls)
        self.assertFalse(any("sudo" in str(call) or "pfctl" in str(call) or "--nc" in str(call) for call in self.calls))

    def test_old_watchdog_requires_explicit_archive(self):
        self.old.parent.mkdir(parents=True)
        self.old.write_bytes(plistlib.dumps({"Label": "com.ali.v2box-vpn-guard"}))
        with self.assertRaises(SystemExit): self.invoke("--install-start-at-login")
        self.assertTrue(self.old.exists())
        self.assertEqual(self.calls, [])

    def test_archive_preserves_old_watchdog_and_only_unloads_that_label(self):
        self.old.parent.mkdir(parents=True)
        original = plistlib.dumps({"Label": "com.ali.v2box-vpn-guard", "RunAtLoad": True})
        self.old.write_bytes(original)
        self.invoke("--install-start-at-login", "--archive-old-watchdog")
        self.assertFalse(self.old.exists())
        archives = list((self.home / "Library/Application Support/V2BoxReconnectTracker").glob("install-backup-*/*.plist"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].read_bytes(), original)
        self.assertIn(("/bin/launchctl", "bootout", "gui/502/com.ali.v2box-vpn-guard"), self.calls)

    def test_existing_install_not_overwritten(self):
        self.agent.parent.mkdir(parents=True)
        self.agent.write_text("existing sentinel")
        with self.assertRaises(SystemExit): self.invoke("--install-start-at-login")
        self.assertEqual(self.agent.read_text(), "existing sentinel")
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
