"""Privileged backend executable implementation. Importing does not run commands.

NOT installed or activated by build/tests. Experimental macOS 13+ only. The CLI
uses fixed root-owned paths and requires root, reviewed config and PF preflight.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

from audit import AuditJournal
from backend_api import BackendAPI
from controller import Controller, ControllerError, StateStore
from coordinator import Coordinator
from endpoints import approved_config
from gateways import physical_devices, discover_active
from pf_driver import PFDriver
from policy import compile_policy, compile_quarantine
from token_store import TokenStore

DIRECTORY = Path("/Library/Application Support/V2BoxGuard")


def run(args, input=None, timeout=8):
    return subprocess.run(args, input=input, text=True, capture_output=True,
                          timeout=timeout, check=False,
                          env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})


def trusted_directory(path):
    current = Path(path)
    while True:
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ControllerError("untrusted deployment directory")
        if current.parent == current:
            return
        current = current.parent


def read_config(directory):
    fd = os.open(directory / "approved.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or
                not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise ControllerError("untrusted approved configuration")
        data = source.read(65537)
    if len(data) > 65536:
        raise ControllerError("oversized configuration")
    config = json.loads(data)
    if (not isinstance(config, dict) or set(config) != {"service_uuid", "service_name", "profile", "inventory", "experimental_ack"}
            or config["experimental_ack"] != "I accept experimental PF behavior"):
        raise ControllerError("reviewed experimental configuration required")
    if not isinstance(config["service_uuid"], str) or not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", config["service_uuid"]):
        raise ControllerError("invalid registered service UUID")
    if not isinstance(config["service_name"], str) or not re.fullmatch(r"[A-Za-z0-9 _-]{1,64}", config["service_name"]):
        raise ControllerError("invalid service name")
    if not isinstance(config["profile"], str):
        raise ControllerError("invalid profile")
    return config


class Runtime:
    def __init__(self, controller, runner, config_reader, now=time.time, trial_reader=None, audit=None):
        self.controller = controller
        self.runner = runner
        self.config_reader = config_reader
        self.now = now
        self.trial_reader = trial_reader
        self.api = BackendAPI(controller)
        self.audit = audit
        self.audit_error = False
        self.stage = "read_config"

    def event(self, operation, stage, outcome, reason="none"):
        self.stage = stage
        if self.audit is not None:
            try: self.audit.record(operation, stage, outcome, reason)
            except Exception: self.audit_error = True

    def diagnostic_reply(self, result):
        result["diagnostic_recording"] = ("not_configured" if self.audit is None else
                                          "unavailable" if self.audit_error else "available")
        return result

    def diagnostic_status(self, result):
        if self.audit is None:
            result["diagnostic_history"] = "not_configured"
            return
        try:
            data = self.audit.read()
            result["diagnostic_history"] = "available"
            last = data["last_failure"]
            if last is not None:
                for field in ("operation", "stage", "outcome", "reason"):
                    result["last_failure_" + field] = last[field]
                result["last_failure_unix"] = str(last["last_unix"])
        except Exception:
            result["diagnostic_history"] = "unavailable"

    def checked(self, args):
        result = self.runner(args)
        if result.returncode:
            raise ControllerError("native discovery failed")
        return result.stdout

    def snapshot(self, config):
        self.stage = "discover_interfaces"
        ports = physical_devices(self.checked(["/usr/sbin/networksetup", "-listallhardwareports"]))
        physical = []
        for device in ports:
            text = self.checked(["/sbin/ifconfig", device])
            if re.search(r"(?m)^\s*status: active\s*$", text):
                physical.append(device)
        self.stage = "discover_gateways"
        gateways = discover_active(self.runner)
        self.stage = "discover_vpn"
        status = self.checked(["/usr/sbin/scutil", "--nc", "status", config["service_uuid"]])
        tunnel = None
        if status.splitlines() and status.splitlines()[0].strip() == "Connected":
            self.stage = "discover_tunnel"
            text = self.checked(["/sbin/ifconfig", "-v"])
            current = None
            matches = []
            for line in text.splitlines():
                header = re.match(r"^(\S+):", line)
                if header:
                    current = header.group(1)
                if (current and re.fullmatch(r"utun[0-9]+", current)
                        and f'desc:"VPN: {config["service_name"]}"' in line
                        and "NetworkExtension type:VPN" in line):
                    matches.append(current)
            if len(matches) != 1:
                raise ControllerError("current tunnel identity is not unique")
            tunnel = matches[0]
        return {"physical": physical, "tunnel": tunnel, "gateways": gateways}

    def preflight(self):
        self.stage = "check_token"
        if self.controller is not None:
            backend = self.controller.backend
            token = backend.tokens.read()  # Reject wrong-boot/corrupt journal first.
            if token == "pending":
                raise ControllerError("PF token acquisition is unresolved")
            if token is not None and not backend.snapshot()["pf_enabled"]:
                raise ControllerError("owned PF token is stale; reconciliation required")
        # Never flush established unrelated states to make activation possible.
        self.stage = "check_states"
        if self.checked(["/sbin/pfctl", "-s", "states"]).strip():
            raise ControllerError("preexisting PF states require separate review")
        self.stage = "check_skip"
        flags = self.checked(["/sbin/pfctl", "-s", "Interfaces", "-v"])
        if re.search(r"\bskip\b", flags, re.I):
            raise ControllerError("PF skip interfaces require separate review")
        # A legacy re-enabler ignores the new persisted Disable setting.
        self.stage = "check_legacy"
        legacy = self.runner(["/bin/launchctl", "print", "system/com.p30arena.v2box-killswitch.refresh"])
        if legacy.returncode == 0:
            raise ControllerError("legacy PF refresher must be removed before deployment")

    def dispatch(self, operation):
        self.audit_error = False
        if operation == "disable":
            self.event(operation, "disable_enforcement", "started")
            try:
                result = self.api.dispatch("disable")
            except Exception:
                self.event(operation, "disable_enforcement", "failed", "enforcement_failed")
                raise  # Never claim Off after an enforcement/removal failure.
            self.event(operation, "disable_enforcement", "ok")
            return self.diagnostic_reply(result)
        if operation == "status":
            result = self.api.dispatch("status")
            self.diagnostic_status(result)
            if self.trial_reader is not None:
                try:
                    trial = self.trial_reader()
                    verdict = trial.get("verdict", "not_started")
                    allowed = {"not_started", "inconclusive", "limited_ipv4_pass"}
                    result["trial_verdict"] = verdict if verdict in allowed else "inconclusive"
                except Exception:
                    result["trial_verdict"] = "unavailable"
            try:
                config = self.config_reader()
                base = self.snapshot(config)
                expected = compile_policy(approved_config(base, config["inventory"], config["profile"], self.now()))
                self.preflight()
                # Only advertise enable after discovery and syntax checks.
                backend = self.controller.backend
                if not backend._root_has_gate():
                    raise ControllerError("root anchor unavailable")
                canonical = backend._call("-n", "-v", "-a", "com.p30arena.v2box-killswitch", "-f", "-", text=expected)
                actual = backend._call("-a", "com.p30arena.v2box-killswitch", "-sr")
                if result["state"] == "on" and actual.strip() != canonical.strip():
                    quarantine = backend._call("-n", "-v", "-a", "com.p30arena.v2box-killswitch", "-f", "-", text=compile_quarantine(base))
                    if actual.strip() != quarantine.strip():
                        result["state"] = "error"
                result["can_enable"] = "true"
            except Exception:
                result["can_enable"] = "false"
                if result["state"] == "on":
                    result["state"] = "error"
            return result
        if operation not in ("enable", "refresh"):
            raise ValueError("unsupported backend operation")
        if operation == "refresh" and not self.controller.store.read():
            return self.api.dispatch("status")
        try:
            self.stage = "read_config"
            config = self.config_reader()
            base = self.snapshot(config)
            if operation == "enable":
                self.preflight()
                self.stage = "validate_approval"
                approved = approved_config(base, config["inventory"], config["profile"], self.now())
                self.event(operation, "enable_enforcement", "started")
                result = self.api._reply(self.controller.enable(approved))
                self.event(operation, "enable_enforcement", "ok")
            else:
                # No enforcement decisions depend on the diagnostic callback.
                result = self.api._reply(Coordinator(self.controller,
                    audit=lambda stage, outcome, reason: self.event(operation, stage, outcome, reason)).update(
                        base, config["inventory"], config["profile"], self.now()))
            return self.diagnostic_reply(result)
        except Exception:
            self.event(operation, self.stage, "failed", "operation_failed")
            if operation == "refresh":
                self.event(operation, "fallback_quarantine", "started", "runtime_failure")
                try:
                    quarantined = self.controller.quarantine({})
                except Exception:
                    self.event(operation, "fallback_quarantine", "failed", "enforcement_failed")
                    raise
                self.event(operation, "fallback_quarantine",
                           "quarantined" if quarantined["state"] == "on" else "skipped_disabled", "runtime_failure")
            raise


def read_trial_summary(directory):
    path = directory / "first-test/observation.json"
    if not path.exists(): return {"verdict": "not_started"}
    raw = path.read_bytes()
    if len(raw) > 16384: raise ControllerError("trial report oversized")
    report = json.loads(raw)
    if report.get("verdict") == "limited_ipv4_pass" and not (directory / "first-test/confirmed").exists():
        return {"verdict": "inconclusive"}
    return report


def main():
    # This is the ONLY real execution entrypoint. Building/importing never calls it.
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in ("status", "enable", "disable", "refresh"):
        return 1
    try:
        trusted_directory(DIRECTORY)
        state_dir = DIRECTORY / "state"
        trusted_directory(state_dir)
        if stat.S_IMODE(state_dir.stat().st_mode) != 0o700:
            raise ControllerError("state directory must have mode 0700")
        # All subprocess calls and token operations share this outer lock.
        fd = os.open(state_dir / "runtime.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            audit = AuditJournal(state_dir)
            try:
                boot = run(["/usr/sbin/sysctl", "-n", "kern.boottime"])
                match = re.search(r"sec\s*=\s*(\d+),\s*usec\s*=\s*(\d+)", boot.stdout)
                if boot.returncode or not match:
                    raise ControllerError("trusted boot identity unavailable")
                tokens = TokenStore(state_dir, ":".join(match.groups()))
                controller = Controller(StateStore(state_dir), PFDriver(run, tokens))
                runtime = Runtime(controller, run, lambda: read_config(DIRECTORY), audit=audit,
                                  trial_reader=lambda: read_trial_summary(DIRECTORY))
            except Exception:
                try: audit.record("backend", "backend_init", "failed", "operation_failed")
                except Exception: pass
                return 1
            print(json.dumps(runtime.dispatch(sys.argv[1])))
        return 0
    except Exception:
        # Do not leak configuration/profile contents in helper output.
        return 1
