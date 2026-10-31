import sys
import tempfile
import threading
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from controller import Controller, ControllerError, StateStore

CONFIG = {"physical": ["en0"], "tunnel": None,
          "endpoints": [{"address": "1.1.1.1", "port": 443, "protocol": "tcp"}]}


class FakePF:
    def __init__(self):
        self.rules = None
        self.other_owner = True
        self.token = False
        self.calls = []
        self.fail_remove = False

    def snapshot(self):
        return {"pf_enabled": self.other_owner or self.token, "anchor_active": self.rules is not None}

    def replace(self, rules):
        self.calls.append("replace")
        self.rules = rules

    def acquire(self):
        self.calls.append("acquire")
        self.token = True

    def remove(self):
        self.calls.append("remove")
        if self.fail_remove:
            raise ControllerError("simulated kernel error")
        self.rules = None

    def release(self):
        self.calls.append("release")
        self.token = False


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = StateStore(self.temp.name)
        self.pf = FakePF()
        self.controller = Controller(self.store, self.pf)

    def test_fresh_install_does_not_enable(self):
        self.assertEqual(self.controller.refresh(CONFIG)["state"], "off")
        self.assertEqual(self.pf.calls, [])

    def test_disable_preserves_other_pf_owner(self):
        self.assertEqual(self.controller.enable(CONFIG)["state"], "on")
        self.assertEqual(self.controller.disable()["state"], "off")
        self.assertTrue(self.pf.snapshot()["pf_enabled"])
        self.assertFalse(self.pf.token)

    def test_restart_does_not_reenable_after_disable(self):
        self.controller.enable(CONFIG)
        self.controller.disable()
        restarted = Controller(StateStore(self.temp.name), self.pf)
        self.pf.calls.clear()
        self.assertEqual(restarted.refresh(CONFIG)["state"], "off")
        self.assertEqual(self.pf.calls, [])

    def test_removal_failure_is_not_reported_off(self):
        self.controller.enable(CONFIG)
        self.pf.fail_remove = True
        with self.assertRaises(ControllerError):
            self.controller.disable()
        self.assertFalse(self.store.read())
        self.assertEqual(self.controller.status()["state"], "error")
        self.pf.calls.clear()
        self.controller.refresh(CONFIG)
        self.assertEqual(self.pf.calls, [])
        self.pf.fail_remove = False
        self.assertEqual(self.controller.disable()["state"], "off")

    def test_corrupt_state_never_reenables(self):
        (Path(self.temp.name) / "intent.json").write_text("broken")
        with self.assertRaises(ControllerError):
            self.controller.refresh(CONFIG)
        self.assertEqual(self.pf.calls, [])
        # Explicit disable is still available with broken intent.
        self.assertEqual(self.controller.disable()["state"], "off")

    def test_missing_actual_enforcement_shows_error(self):
        self.controller.enable(CONFIG)
        self.pf.rules = None
        self.assertEqual(self.controller.status()["state"], "error")

    def test_invalid_config_does_not_enable(self):
        with self.assertRaises(ValueError):
            self.controller.enable({})
        self.assertFalse(self.store.read())
        self.assertEqual(self.pf.calls, [])

    def test_refresh_and_disable_serialized(self):
        self.controller.enable(CONFIG)
        errors = []
        def refresh():
            try:
                for _ in range(30):
                    self.controller.refresh(CONFIG)
            except Exception as exc:
                errors.append(exc)
        worker = threading.Thread(target=refresh)
        worker.start()
        self.controller.disable()
        worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(self.controller.status()["state"], "off")
        self.assertIsNone(self.pf.rules)


if __name__ == "__main__":
    unittest.main()
