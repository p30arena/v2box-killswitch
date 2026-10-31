from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from backend_api import BackendAPI


class Controller:
    def __init__(self): self.calls = []; self.fail = False
    def status(self):
        self.calls.append("status")
        if self.fail: raise RuntimeError("private error")
        return {"state": "error", "policy_mode": "quarantine"}
    def disable(self):
        self.calls.append("disable")
        if self.fail: raise RuntimeError("removal failed")
        return {"state": "off"}


class BackendAPITests(unittest.TestCase):
    def setUp(self):
        self.controller = Controller()
        self.api = BackendAPI(self.controller)

    def test_fixed_capabilities_and_string_reply(self):
        result = self.api.dispatch("status")
        self.assertEqual(result["can_enable"], "false")
        self.assertEqual(result["can_disable"], "true")
        self.assertTrue(all(isinstance(x, str) for x in result.values()))

    def test_broken_status_still_offers_authorized_disable(self):
        self.controller.fail = True
        result = self.api.dispatch("status")
        self.assertEqual(result["state"], "error")
        self.assertEqual(result["can_disable"], "true")
        self.assertNotIn("private", str(result))

    def test_disable_success(self):
        self.assertEqual(self.api.dispatch("disable")["state"], "off")
        self.assertEqual(self.controller.calls, ["disable"])

    def test_disable_failure_not_reported_as_off(self):
        self.controller.fail = True
        with self.assertRaises(RuntimeError): self.api.dispatch("disable")

    def test_no_arbitrary_operations(self):
        for action in ("enable", "reconnect", "pfctl -F all", "../config", "status; anything"):
            with self.subTest(action=action), self.assertRaises(ValueError): self.api.dispatch(action)
        self.assertEqual(self.controller.calls, [])


if __name__ == "__main__": unittest.main()
