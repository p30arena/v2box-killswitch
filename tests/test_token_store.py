import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from controller import ControllerError
from token_store import TokenStore


class TokenStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.directory.chmod(0o700)
        self.store = TokenStore(self.directory, "boot-one", expected_uid=os.getuid())
        self.path = self.directory / TokenStore.NAME

    def test_missing_means_no_owned_token(self):
        self.assertIsNone(self.store.read())

    def test_roundtrip_acquisition_and_release_journal(self):
        for value in ("pending", "12345", None):
            self.store.write(value)
            restarted = TokenStore(self.directory, "boot-one", expected_uid=os.getuid())
            self.assertEqual(restarted.read(), value)
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_other_boot_never_reuses_or_releases_token(self):
        self.store.write("12345")
        other = TokenStore(self.directory, "boot-two", expected_uid=os.getuid())
        with self.assertRaises(ControllerError): other.read()

    def test_pending_survives_restart(self):
        self.store.write("pending")
        self.assertEqual(TokenStore(self.directory, "boot-one", expected_uid=os.getuid()).read(), "pending")

    def test_symlink_file_rejected(self):
        outside = self.directory / "outside"
        outside.write_text("secret")
        self.path.symlink_to(outside)
        with self.assertRaises(OSError): self.store.read()
        self.assertEqual(outside.read_text(), "secret")

    def test_hardlink_rejected(self):
        self.store.write("12345")
        os.link(self.path, self.directory / "alias")
        with self.assertRaises(ControllerError): self.store.read()

    def test_world_readable_file_rejected(self):
        self.store.write("12345")
        self.path.chmod(0o644)
        with self.assertRaises(ControllerError): self.store.read()

    def test_unsafe_directory_rejected(self):
        self.directory.chmod(0o755)
        with self.assertRaises(ControllerError): self.store.read()
        with self.assertRaises(ControllerError): self.store.write("12345")

    def test_corrupt_record_rejected(self):
        self.store.write("12345")
        for text in ("broken", "[]", json.dumps({"version": True, "boot_id": "boot-one", "token": "12345"})):
            self.path.write_text(text)
            with self.assertRaises(ControllerError): self.store.read()

    def test_oversize_record_rejected(self):
        self.store.write("12345")
        self.path.write_text(" " * 5000)
        with self.assertRaises(ControllerError): self.store.read()

    def test_invalid_values_rejected(self):
        for value in (True, 123, "-X 42", "", "9" * 21):
            with self.subTest(value=value), self.assertRaises(ControllerError): self.store.write(value)

    def test_driver_restart_uses_existing_reference(self):
        from pf_driver import PFDriver
        from test_pf_driver import Kernel
        kernel = Kernel()
        PFDriver(kernel.run, self.store).acquire()
        restarted = TokenStore(self.directory, "boot-one", expected_uid=os.getuid())
        PFDriver(kernel.run, restarted).acquire()
        self.assertEqual(sum(args == ["-E"] for args, _ in kernel.calls), 1)
        PFDriver(kernel.run, restarted).release()
        self.assertIsNone(restarted.read())

    def test_different_boot_does_not_call_pf(self):
        from pf_driver import PFDriver
        from test_pf_driver import Kernel
        self.store.write("12345")
        other = TokenStore(self.directory, "boot-two", expected_uid=os.getuid())
        kernel = Kernel()
        driver = PFDriver(kernel.run, other)
        with self.assertRaises(ControllerError): driver.acquire()
        with self.assertRaises(ControllerError): driver.release()
        self.assertEqual(kernel.calls, [])

    def test_interrupted_replace_preserves_old_record(self):
        self.store.write("pending")
        with patch("token_store.os.replace", side_effect=OSError("simulated interruption")):
            with self.assertRaises(OSError): self.store.write("12345")
        self.assertEqual(self.store.read(), "pending")
        self.assertFalse(list(self.directory.glob(".pf-token-*")))


if __name__ == "__main__": unittest.main()
