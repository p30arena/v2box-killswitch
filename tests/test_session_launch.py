from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from session_launch import CHECKS, ENVIRONMENT, check_user_launch, identity_argv


class SessionLaunchTests(unittest.TestCase):
    def setUp(self):
        self.values = {"effective_uid": "501", "real_uid": "501", "effective_gid": "20",
                       "real_gid": "20", "groups": "20 80", "bootstrap_uid": "501", "session_type": "Aqua"}
        self.calls = []
        self.code = 0
        self.error = None

    def fake_run(self, argv, timeout, env):
        self.calls.append((argv, timeout, env))
        if self.error: raise self.error
        check = next(key for key, value in CHECKS.items() if list(value) == argv[8:])
        return SimpleNamespace(returncode=self.code, stdout=self.values[check] + "\n", stderr="private detail")

    def check_launch(self): return check_user_launch(501, 20, {20, 80, 81}, self.fake_run)

    def test_fixed_scoped_read_only_launch_plan(self):
        self.assertTrue(self.check_launch().verified)
        self.assertEqual(len(self.calls), 7)
        for argv, timeout, env in self.calls:
            self.assertEqual(argv[:8], ["/bin/launchctl", "asuser", "501", "/usr/bin/sudo", "-n", "-u", "#501", "--"])
            self.assertIn(tuple(argv[8:]), CHECKS.values())
            self.assertEqual(timeout, 4)
            self.assertEqual(env, ENVIRONMENT)
            self.assertNotIn("/usr/sbin/scutil", argv)
            self.assertNotIn("/sbin/pfctl", argv)
            self.assertNotIn("/bin/sh", argv)

    def test_root_invalid_uid_and_arbitrary_operation_rejected(self):
        for uid in (0, -1, True, "501", 4294967295):
            with self.assertRaises(ValueError): identity_argv("effective_uid", uid)
        for operation in ("start", "bootstrap", "/bin/sh", None):
            with self.assertRaises(ValueError): identity_argv(operation, 501)
        self.assertEqual(self.calls, [])

    def test_uid_and_bootstrap_mismatches_fail(self):
        for key in ("effective_uid", "real_uid", "bootstrap_uid"):
            self.setUp(); self.values[key] = "0"
            result = self.check_launch()
            self.assertFalse(result.verified)
            self.assertEqual(result.reason, "user_identity_mismatch")

    def test_group_mismatch_fails(self):
        for key in ("effective_gid", "real_gid"):
            self.setUp(); self.values[key] = "0"
            self.assertEqual(self.check_launch().reason, "primary_group_mismatch")

    def test_unexpected_inherited_group_fails(self):
        self.values["groups"] = "0 20 80"
        self.assertEqual(self.check_launch().reason, "supplementary_group_mismatch")

    def test_missing_membership_does_not_add_privilege(self):
        self.values["groups"] = "20"
        self.assertTrue(self.check_launch().verified)

    def test_background_bootstrap_is_not_gui_session(self):
        self.values["session_type"] = "Background"
        self.assertEqual(self.check_launch().reason, "bootstrap_session_mismatch")

    def test_bad_outputs_are_not_accepted(self):
        for value in ("501\n0", "true", "+501", "501;anything", "x"*4097):
            self.values["effective_uid"] = value
            self.assertFalse(self.check_launch().verified)
        self.values["effective_uid"] = "501"
        for value in ("", "20 bogus", "20 -1", "20 4294967295"):
            self.values["groups"] = value
            self.assertFalse(self.check_launch().verified)

    def test_error_and_timeout_do_not_leak_output_or_retry(self):
        for error in (RuntimeError("private credentials"), TimeoutError("private session")):
            self.setUp(); self.error = error
            result = self.check_launch()
            self.assertEqual(result.reason, "launch_unavailable")
            self.assertNotIn("private", repr(result))
            self.assertEqual(len(self.calls), 1)

    def test_nonzero_exit_never_means_validated_identity(self):
        self.code = 1
        self.assertFalse(self.check_launch().verified)
        self.assertEqual(len(self.calls), 1)

    def test_invalid_account_expectations_fail_before_execution(self):
        for gid, groups in ((True, {20}), (-1, {20}), (20, [20]), (20, {True}), (20, set(range(1025)))):
            with self.assertRaises(ValueError): check_user_launch(501, gid, groups, self.fake_run)
        self.assertEqual(self.calls, [])


if __name__ == "__main__": unittest.main()
