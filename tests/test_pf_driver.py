import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from controller import ControllerError
from pf_driver import ANCHOR, PFDriver
from policy import compile_policy

CONFIG = {"physical": ["en0"], "endpoints": [{"address": "1.1.1.1", "port": 443, "protocol": "tcp"}]}


class Tokens:
    def __init__(self): self.value = None
    def read(self): return self.value
    def write(self, value): self.value = value


class Kernel:
    def __init__(self):
        self.calls = []
        self.rules = ""
        self.root = f'anchor "{ANCHOR}" all quick\nanchor "com.apple/*" all\n'
        self.enabled = True
        self.fail = None
        self.token_output = "Token : 12345\n"
        self.other_rules = "unrelated sentinel"

    def run(self, args, input):
        self.calls.append((args[1:], input))
        command = args[1:]
        if self.fail == command:
            return SimpleNamespace(returncode=1, stdout="", stderr="failure")
        out, err = "", ""
        if command == ["-sr"]: out = self.root
        elif command == ["-s", "info"]: out = "Status: " + ("Enabled" if self.enabled else "Disabled") + " for 0 days\n"
        elif command == ["-a", ANCHOR, "-sr"]: out = self.rules
        elif command == ["-n", "-a", ANCHOR, "-f", "-"]: pass
        elif command == ["-a", ANCHOR, "-f", "-"]: self.rules = input
        elif command == ["-E"]: self.enabled = True; err = self.token_output
        elif command == ["-X", "12345"]: pass  # another owner keeps PF enabled
        else: raise AssertionError(command)
        return SimpleNamespace(returncode=0, stdout=out, stderr=err)


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.kernel = Kernel()
        self.tokens = Tokens()
        self.driver = PFDriver(self.kernel.run, self.tokens)

    def test_replace_only_scoped_anchor(self):
        self.driver.replace(compile_policy(CONFIG))
        self.assertTrue(self.driver.snapshot()["anchor_active"])
        self.assertEqual(self.kernel.other_rules, "unrelated sentinel")
        for args, _ in self.kernel.calls:
            self.assertNotIn("-F", args)
            self.assertNotIn("-d", args)

    def test_nonquick_gate_rejected_before_update(self):
        self.kernel.root = self.kernel.root.replace(" all quick", " all")
        with self.assertRaises(ControllerError): self.driver.replace(compile_policy(CONFIG))
        self.assertEqual(self.kernel.rules, "")

    def test_preceding_rule_rejected(self):
        self.kernel.root = "pass out all\n" + self.kernel.root
        with self.assertRaises(ControllerError): self.driver.replace(compile_policy(CONFIG))

    def test_acquire_once_release_only_owned_reference(self):
        self.driver.acquire(); self.driver.acquire()
        self.assertEqual(sum(args == ["-E"] for args, _ in self.kernel.calls), 1)
        self.driver.release()
        self.assertIsNone(self.tokens.value)
        self.assertTrue(self.kernel.enabled)
        self.assertIn((["-X", "12345"], None), self.kernel.calls)

    def test_unknown_token_never_reacquired(self):
        self.kernel.token_output = "unrecognized output"
        with self.assertRaises(ControllerError): self.driver.acquire()
        with self.assertRaises(ControllerError): self.driver.acquire()
        self.assertEqual(sum(args == ["-E"] for args, _ in self.kernel.calls), 1)
        self.assertEqual(self.tokens.value, "pending")

    def test_failed_release_preserves_token(self):
        self.driver.acquire()
        self.kernel.fail = ["-X", "12345"]
        with self.assertRaises(ControllerError): self.driver.release()
        self.assertEqual(self.tokens.value, "12345")

    def test_remove_works_even_when_token_unknown(self):
        self.driver.replace(compile_policy(CONFIG))
        self.tokens.value = "pending"
        self.driver.remove()
        self.assertEqual(self.kernel.rules, "")
        with self.assertRaises(ControllerError): self.driver.release()

    def test_stale_token_not_silently_reacquired(self):
        self.tokens.value = "12345"
        self.kernel.enabled = False
        with self.assertRaises(ControllerError): self.driver.acquire()
        self.assertFalse(any(args == ["-E"] for args, _ in self.kernel.calls))

    def test_syntax_failure_does_not_replace(self):
        self.kernel.fail = ["-n", "-a", ANCHOR, "-f", "-"]
        with self.assertRaises(ControllerError): self.driver.replace(compile_policy(CONFIG))
        self.assertEqual(self.kernel.rules, "")


if __name__ == "__main__": unittest.main()
