"""Read-only native worker tests. No VPN commands, root, services or PF writes."""
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from controller import ControllerError
from process_observer import KernelProcessObserver
from recovery_broker import Completion
from recovery_store import PendingCommandStore
from recovery_witness import ChildWitnessStore, WitnessGate

BINARY = str(Path(sys.argv.pop(1)).resolve())
TICKET = "a" * 32
SERVICE = "00000000-0000-0000-0000-000000000000"


class ProbeDialogue:
    """Private pipes to our own unprivileged diagnostic worker; no PID signalling."""
    def __init__(self, fixture):
        self.proc = subprocess.Popen([BINARY, "--supervise-probe", TICKET, str(os.geteuid()), fixture],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.buffer = b""

    def __enter__(self): return self

    def frame(self, timeout=6):
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(self.proc.stdout, selectors.EVENT_READ)
            while b"\n" not in self.buffer:
                if time.monotonic() >= deadline: raise AssertionError("worker frame deadline")
                if selector.select(timeout=0.05):
                    chunk = os.read(self.proc.stdout.fileno(), 4096)
                    if not chunk: raise AssertionError("worker exited before frame")
                    self.buffer += chunk
                    if len(self.buffer) > 4096: raise AssertionError("oversized worker output")
        line, self.buffer = self.buffer.split(b"\n", 1)
        frame = json.loads(line)
        if frame["can_execute"] is not False: raise AssertionError("VPN execution enabled")
        if frame.get("ticket") != TICKET: raise AssertionError("mismatched worker ticket")
        return frame

    def send(self, data):
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def close_input(self):
        if self.proc.stdin is not None:
            self.proc.stdin.close(); self.proc.stdin = None

    def finish(self):
        self.close_input()
        out, err = self.proc.communicate(timeout=4)
        if out or self.buffer or err: raise AssertionError("unexpected trailing worker output")
        return self.proc.returncode

    def __exit__(self, *exc):
        self.close_input()
        try:
            self.proc.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            # Only our still-unreaped worker. No signalling a reported child PID.
            self.proc.kill(); self.proc.wait(timeout=3)
        finally:
            for stream in (self.proc.stdout, self.proc.stderr):
                if stream is not None: stream.close()


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

    def stage_probe(self, dialogue):
        self.assertEqual(dialogue.frame()["phase"], "ready")
        dialogue.send(("GRANT " + TICKET + "\n").encode())
        staged = dialogue.frame()
        self.assertEqual(staged["phase"], "probe_staged")
        self.assertIs(type(staged["child_pid"]), int)
        self.assertGreater(staged["child_pid"], 0)
        self.assertNotEqual(staged["child_pid"], dialogue.proc.pid)
        self.assertGreater(staged["child_birth_seconds"], 0)
        self.assertLess(staged["child_birth_microseconds"], 1_000_000)
        dialogue.staged = staged
        return staged["child_pid"]

    def staging_expectations(self, dialogue, worker):
        stage = dialogue.staged
        return dict(worker=worker, child={"pid": stage["child_pid"],
                    "birth_seconds": stage["child_birth_seconds"],
                    "birth_microseconds": stage["child_birth_microseconds"]},
                    uid=self.uid, primary_gid=os.getgid(), worker_parent_pid=os.getpid())

    def test_parent_independently_observes_staged_worker_and_child(self):
        self.require_session()
        observer = KernelProcessObserver()
        with ProbeDialogue("identity") as dialogue:
            worker = observer.observe(dialogue.proc.pid).identity()
            child = self.stage_probe(dialogue)
            expected = self.staging_expectations(dialogue, worker)
            observed = observer.verify_staged(**expected)
            self.assertEqual(observed["child"], expected["child"])
            self.assertEqual(observed["worker"], worker)
            dialogue.send(("CANCEL " + TICKET + "\n").encode())
            self.assert_probe_reaped(dialogue.frame(), child)
            self.assertEqual(dialogue.finish(), 0)
            # Missing PID remains observation failure, NOT completion proof.
            with self.assertRaises(ControllerError): observer.observe(child)

    def test_parent_rejects_reported_birth_parent_or_user_mismatch(self):
        self.require_session()
        observer = KernelProcessObserver()
        with ProbeDialogue("identity") as dialogue:
            worker = observer.observe(dialogue.proc.pid).identity()
            child = self.stage_probe(dialogue)
            expected = self.staging_expectations(dialogue, worker)
            bad_child = dict(expected["child"], birth_seconds=expected["child"]["birth_seconds"] + 1)
            for override in ({"child": bad_child}, {"worker_parent_pid": dialogue.proc.pid}, {"uid": self.uid + 1}):
                with self.assertRaises(ControllerError): observer.verify_staged(**dict(expected, **override))
            dialogue.send(("CANCEL " + TICKET + "\n").encode())
            self.assert_probe_reaped(dialogue.frame(), child)
            self.assertEqual(dialogue.finish(), 0)

    def test_parent_observer_does_not_accept_resumed_child_as_staged(self):
        self.require_session()
        observer = KernelProcessObserver()
        with ProbeDialogue("wait") as dialogue:
            worker = observer.observe(dialogue.proc.pid).identity()
            child = self.start_probe(dialogue)
            with self.assertRaises(ControllerError):
                observer.verify_staged(**self.staging_expectations(dialogue, worker))
            dialogue.send(("CANCEL " + TICKET + "\n").encode())
            self.assert_probe_reaped(dialogue.frame(), child)
            self.assertEqual(dialogue.finish(), 0)

    def test_fixture_kernel_observation_and_temp_witness_before_exec(self):
        self.require_session()
        # Unprivileged scratch state and FIXTURE authorization only. No real
        # enforcement approval, code pin or authenticated production bridge.
        observer = KernelProcessObserver()
        with tempfile.TemporaryDirectory() as directory, threading.Lock():
            pending = PendingCommandStore(directory, "fixture-boot", expected_uid=self.uid)
            witness = ChildWitnessStore(directory, "fixture-boot", expected_uid=self.uid)
            pending.write({"ticket": TICKET, "uid": self.uid})
            with ProbeDialogue("identity") as dialogue:
                worker = observer.observe(dialogue.proc.pid).identity()
                child = self.stage_probe(dialogue)
                expected = self.staging_expectations(dialogue, worker)
                def fixture_authorization():
                    observer.verify_staged(**expected)
                    return True  # Read-only fixture, NOT actual PF/intent authorization.
                gate = WitnessGate(pending, witness, fixture_authorization)
                value = {"ticket": TICKET, "uid": self.uid, "worker": worker, "child": expected["child"]}
                frame = gate.grant(value)
                self.assertEqual(witness.read()["phase"], "grant_recorded")
                dialogue.send(frame)
                self.assertEqual(dialogue.frame()["phase"], "probe_started")
                result = dialogue.frame()
                self.assert_probe_reaped(result, child)
                self.assertEqual(result["exit_code"], 0)
                proof = gate.finish(value, Completion(TICKET, self.uid, True, result["exit_code"]))
                self.assertTrue(proof.terminated)
                self.assertEqual(witness.read()["phase"], "completed")
                self.assertIsNotNone(pending.read())
                pending.clear(TICKET, self.uid)  # Broker-owned step modeled explicitly.
                self.assertIsNone(pending.read())
                self.assertEqual(dialogue.finish(), 0)

    def start_probe(self, dialogue):
        child = self.stage_probe(dialogue)
        dialogue.send(("EXEC " + TICKET + "\n").encode())
        started = dialogue.frame()
        self.assertEqual(started["phase"], "probe_started")
        self.assertEqual(started["child_pid"], child)
        return child

    def assert_probe_reaped(self, frame, child):
        self.assertEqual(frame["phase"], "probe_finished")
        self.assertIs(frame["child_terminated"], True)
        self.assertEqual(frame["child_pid"], child)
        # Signal ZERO is a read-only existence check, not a kill. PID reuse would
        # fail this conservative assertion, never cause us to signal another PID.
        with self.assertRaises(ProcessLookupError): os.kill(child, 0)

    def test_staged_identity_cannot_run_before_second_execution_grant(self):
        self.require_session()
        with ProbeDialogue("identity") as dialogue:
            child = self.stage_probe(dialogue)
            time.sleep(0.05)
            state = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(child)],
                                   capture_output=True, text=True, timeout=2)
            self.assertEqual(state.returncode, 0)
            self.assertTrue(state.stdout.strip().startswith("T"), "fixture was not suspended")
            dialogue.send(("EXEC " + TICKET + "\n").encode())
            self.assertEqual(dialogue.frame()["phase"], "probe_started")
            frame = dialogue.frame()
            self.assert_probe_reaped(frame, child)
            self.assertEqual(frame["exit_code"], 0)
            self.assertEqual(dialogue.finish(), 0)

    def test_cancel_staged_child_never_resumes_it(self):
        self.require_session()
        with ProbeDialogue("identity") as dialogue:
            child = self.stage_probe(dialogue)
            dialogue.send(("CANCEL " + TICKET + "\n").encode())
            frame = dialogue.frame()
            self.assert_probe_reaped(frame, child)
            self.assertEqual(frame["reason"], "cancelled_by_parent")
            self.assertEqual(frame["exit_code"], -signal.SIGKILL)
            self.assertEqual(dialogue.finish(), 0)

    def test_parent_eof_with_staged_child_cancels_and_reaps(self):
        self.require_session()
        with ProbeDialogue("identity") as dialogue:
            child = self.stage_probe(dialogue)
            dialogue.close_input()
            frame = dialogue.frame()
            self.assert_probe_reaped(frame, child)
            self.assertEqual(frame["reason"], "parent_closed")
            self.assertEqual(dialogue.finish(), 0)

    def test_missing_execution_grant_reaps_staged_child(self):
        self.require_session()
        with ProbeDialogue("identity") as dialogue:
            child = self.stage_probe(dialogue)
            frame = dialogue.frame()
            self.assert_probe_reaped(frame, child)
            self.assertEqual(frame["reason"], "execution_grant_timeout")
            self.assertEqual(frame["exit_code"], -signal.SIGKILL)
            self.assertEqual(dialogue.finish(), 0)

    def test_wrong_execution_grant_cancels_staged_child(self):
        self.require_session()
        with ProbeDialogue("identity") as dialogue:
            child = self.stage_probe(dialogue)
            dialogue.send(("EXEC " + "b"*32 + "\n").encode())
            frame = dialogue.frame()
            self.assert_probe_reaped(frame, child)
            self.assertEqual(frame["reason"], "invalid_control")
            self.assertEqual(dialogue.finish(), 2)

    def test_supervised_identity_child_exits_and_is_reaped(self):
        self.require_session()
        with ProbeDialogue("identity") as dialogue:
            child = self.start_probe(dialogue)
            frame = dialogue.frame()
            self.assert_probe_reaped(frame, child)
            self.assertEqual(frame["reason"], "probe_exited")
            self.assertEqual(frame["exit_code"], 0)
            self.assertEqual(dialogue.finish(), 0)

    def test_supervised_cancel_reaps_only_owned_child(self):
        self.require_session()
        with ProbeDialogue("wait") as dialogue:
            child = self.start_probe(dialogue)
            dialogue.send(("CANCEL " + TICKET + "\n").encode())
            frame = dialogue.frame()
            self.assert_probe_reaped(frame, child)
            self.assertEqual(frame["reason"], "cancelled_by_parent")
            self.assertEqual(frame["exit_code"], -signal.SIGKILL)
            self.assertEqual(dialogue.finish(), 0)

    def test_supervised_parent_eof_cancels_and_reaps(self):
        self.require_session()
        with ProbeDialogue("wait") as dialogue:
            child = self.start_probe(dialogue)
            dialogue.close_input()
            frame = dialogue.frame()
            self.assert_probe_reaped(frame, child)
            self.assertEqual(frame["reason"], "parent_closed")
            self.assertEqual(dialogue.finish(), 0)

    def test_supervised_deadline_cancels_and_reaps(self):
        self.require_session()
        with ProbeDialogue("wait") as dialogue:
            child = self.start_probe(dialogue)
            frame = dialogue.frame()
            self.assert_probe_reaped(frame, child)
            self.assertEqual(frame["reason"], "probe_timeout")
            self.assertEqual(dialogue.finish(), 0)

    def test_supervised_invalid_control_cannot_select_pid_or_spawn_again(self):
        self.require_session()
        for data in (("CANCEL " + "b"*32 + "\n").encode(), b"KILL 1\n", b"x"*65,
                     ("GRANT " + TICKET + "\n").encode()):
            with ProbeDialogue("wait") as dialogue:
                child = self.start_probe(dialogue)
                dialogue.send(data)
                frame = dialogue.frame()
                self.assert_probe_reaped(frame, child)
                self.assertEqual(frame["reason"], "invalid_control")
                self.assertEqual(dialogue.finish(), 2)

    def test_supervised_fragmented_cancel_is_bounded_and_reaped(self):
        self.require_session()
        with ProbeDialogue("wait") as dialogue:
            child = self.start_probe(dialogue)
            dialogue.send(b"CAN")
            time.sleep(0.03)
            dialogue.send(("CEL " + TICKET + "\n").encode())
            frame = dialogue.frame()
            self.assert_probe_reaped(frame, child)
            self.assertEqual(frame["reason"], "cancelled_by_parent")
            self.assertEqual(dialogue.finish(), 0)

    def test_supervised_closed_output_still_reaps_child_before_exit(self):
        self.require_session()
        with ProbeDialogue("wait") as dialogue:
            child = self.start_probe(dialogue)
            dialogue.proc.stdout.close()
            dialogue.send(("CANCEL " + TICKET + "\n").encode())
            self.assertEqual(dialogue.proc.wait(timeout=4), 3)
            with self.assertRaises(ProcessLookupError): os.kill(child, 0)
            # communicate cannot read a deliberately closed stream.
            dialogue.proc.stdout = None

    def test_output_loss_at_execution_grant_still_reaps_owned_child(self):
        self.require_session()
        with ProbeDialogue("wait") as dialogue:
            child = self.stage_probe(dialogue)
            dialogue.proc.stdout.close()
            dialogue.send(("EXEC " + TICKET + "\n").encode())
            self.assertEqual(dialogue.proc.wait(timeout=4), 3)
            with self.assertRaises(ProcessLookupError): os.kill(child, 0)
            dialogue.proc.stdout = None

    def test_parent_eof_before_fixture_grant_never_stages_child(self):
        self.require_session()
        args = [BINARY, "--supervise-probe", TICKET, str(self.uid), "identity"]
        result, frames = self.run_worker(args)
        self.assertEqual(result.returncode, 0)
        self.assertEqual([frame["phase"] for frame in frames], ["ready", "cancelled"])
        self.assertTrue(all("child_pid" not in frame for frame in frames))

    def test_supervision_only_accepts_fixed_read_only_fixtures(self):
        for fixture in ("start", "stop", "/bin/sh", "sleep 100", "1"):
            result, frames = self.run_worker([BINARY, "--supervise-probe", TICKET, str(self.uid), fixture])
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(frames[-1]["reason"], "invalid_request")

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
