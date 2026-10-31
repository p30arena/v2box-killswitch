"""Read-only native worker tests. No VPN commands, root, services or PF writes."""
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())
TICKET = "a" * 32
SERVICE = "00000000-0000-0000-0000-000000000000"


class WorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.uid = os.geteuid()
        if cls.uid == 0: raise unittest.SkipTest("native worker tests require an unprivileged user")
        cls.request = [BINARY, "--prepare", TICKET, str(cls.uid), "start", SERVICE]

    def run_worker(self, args=None, data=b""):
        result = subprocess.run(args or self.request, input=data, capture_output=True, timeout=8)
        frames = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertTrue(frames, result.stderr)
        for frame in frames:
            self.assertIs(frame["can_execute"], False)
            self.assertEqual(frame["version"], 1)
        self.assertNotIn(SERVICE, result.stdout.decode())
        return result, frames

    def require_session(self):
        result, frames = self.run_worker([BINARY, "--probe-session", str(self.uid)])
        if result.returncode != 0 and frames[-1].get("reason") == "session_unverified":
            self.skipTest("not the current Aqua console session; worker correctly refuses")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(frames[-1]["phase"], "identity_verified")
        self.assertEqual(frames[-1]["uid"], self.uid)

    def test_read_only_identity_probe(self):
        self.require_session()

    def test_inherited_blocked_mask_and_ignored_sigchld_are_normalized(self):
        self.require_session()
        def inherited_launcher_state():
            blocked = [signal.SIGINT, signal.SIGTERM, signal.SIGCHLD]
            if hasattr(signal, "SIGINFO"): blocked.append(signal.SIGINFO)
            signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        result = subprocess.run([BINARY, "--probe-session", str(self.uid)], capture_output=True,
                                preexec_fn=inherited_launcher_state, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)
        frame = json.loads(result.stdout)
        self.assertEqual(frame["phase"], "identity_verified")
        self.assertIs(frame["can_execute"], False)

    def test_root_target_is_rejected(self):
        result, frames = self.run_worker([BINARY, "--probe-session", "0"])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(frames[-1]["phase"], "rejected")

    def test_wrong_user_is_rejected(self):
        other = self.uid + 1 if self.uid < 4294967294 else 1
        result, frames = self.run_worker([BINARY, "--probe-session", str(other)])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(frames[-1]["reason"], "session_unverified")

    def test_arbitrary_commands_and_malformed_requests_rejected(self):
        for args in ([BINARY, "/bin/sh"], [BINARY, "--prepare", TICKET, str(self.uid), "start;anything", SERVICE],
                     [BINARY, "--prepare", "bad", str(self.uid), "start", SERVICE],
                     [BINARY, "--prepare", TICKET, str(self.uid), "start", "not-a-service"],
                     [BINARY, "--probe-session", "true"]):
            result, frames = self.run_worker(args)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(frames[-1]["phase"], "rejected")

    def test_parent_eof_cancels_before_execution(self):
        self.require_session()
        result, frames = self.run_worker()
        self.assertEqual(result.returncode, 0)
        self.assertEqual([frame["phase"] for frame in frames], ["ready", "cancelled"])
        self.assertEqual(frames[-1]["reason"], "parent_closed")

    def test_matching_cancel_is_acknowledged(self):
        self.require_session()
        result, frames = self.run_worker(data=("CANCEL " + TICKET + "\n").encode())
        self.assertEqual(result.returncode, 0)
        self.assertEqual(frames[-1]["reason"], "cancelled_by_parent")

    def test_matching_grant_still_cannot_execute_vpn(self):
        self.require_session()
        result, frames = self.run_worker(data=("GRANT " + TICKET + "\n").encode())
        self.assertEqual(result.returncode, 0)
        self.assertEqual(frames[-1]["phase"], "execution_disabled")
        self.assertEqual(frames[-1]["reason"], "prototype_no_executor")

    def test_mismatched_ticket_unknown_verb_and_extra_frames_rejected(self):
        self.require_session()
        for data in (b"GRANT " + b"b"*32 + b"\n", b"RUN /bin/sh\n", b"x"*65,
                     ("GRANT " + TICKET + "\nCANCEL " + TICKET + "\n").encode()):
            result, frames = self.run_worker(data=data)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(frames[-1]["phase"], "rejected")

    def test_partial_grant_then_eof_never_executes(self):
        self.require_session()
        result, frames = self.run_worker(data=("GRANT " + TICKET).encode())
        self.assertEqual(result.returncode, 0)
        self.assertEqual(frames[-1]["reason"], "parent_closed")

    def test_no_grant_times_out_while_parent_pipe_remains_open(self):
        self.require_session()
        proc = subprocess.Popen(self.request, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            data = b""
            until = time.monotonic() + 6
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                while b"\n" not in data:
                    self.assertLess(time.monotonic(), until, "no Ready frame")
                    if selector.select(timeout=0.1):
                        chunk = os.read(proc.stdout.fileno(), 1024)
                        self.assertTrue(chunk, "worker exited before Ready")
                        data += chunk
                        self.assertLess(len(data), 4096)
            first, extra = data.split(b"\n", 1)
            self.assertEqual(json.loads(first)["phase"], "ready")
            # Keep stdin open. Exit must be the worker's own grant deadline.
            self.assertEqual(proc.wait(timeout=6), 0)
            proc.stdin.close(); proc.stdin = None
            out, err = proc.communicate(timeout=2)
            frames = [json.loads(line) for line in (extra + out).splitlines()]
            self.assertEqual(frames[-1]["reason"], "grant_timeout")
            self.assertIs(frames[-1]["can_execute"], False)
        finally:
            if proc.poll() is None: proc.kill(); proc.wait(timeout=3)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None: stream.close()


if __name__ == "__main__": unittest.main()
