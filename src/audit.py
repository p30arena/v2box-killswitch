"""Bounded private diagnostic journal. Caller holds the backend runtime lock.

No networking or enforcement operations. Only enumerated metadata is accepted;
exception text, command output, addresses and profile data are never serialized.
"""
import json
import math
import os
from pathlib import Path
import stat
import tempfile
import time

OPERATIONS = {"enable", "disable", "refresh", "backend", "trial_timer"}
STAGES = {"read_config", "discover_interfaces", "discover_gateways", "discover_vpn",
          "discover_tunnel", "check_token", "check_states", "check_skip", "check_legacy",
          "validate_approval", "enable_enforcement", "disable_enforcement",
          "refresh_enforcement", "approval_quarantine", "fallback_quarantine", "backend_init",
          "trial_wait", "trial_deadline", "trial_syntax", "trial_disable_intent",
          "trial_apply_quarantine", "trial_marker", "diagnostic_preflight"}
OUTCOMES = {"started", "ok", "failed", "quarantined", "skipped_disabled"}
REASONS = {"none", "operation_failed", "approval_required", "policy_invalid",
           "enforcement_failed", "runtime_failure", "disabled_intent", "tunnel_present", "tunnel_absent",
           "activation_timeout", "confirmation_present", "confirmation_missing"}
DIAGNOSTIC_CAPABILITY = "backend_and_trial_timer_v1"
MAX_EVENTS = 128
MAX_BYTES = 65536
KEYS = {"sequence", "operation", "stage", "outcome", "reason", "first_unix", "last_unix", "count"}


def valid_event(event):
    if not isinstance(event, dict) or set(event) != KEYS: return False
    for key, allowed in (("operation", OPERATIONS), ("stage", STAGES), ("outcome", OUTCOMES), ("reason", REASONS)):
        if not isinstance(event[key], str) or event[key] not in allowed: return False
    if any(type(event[k]) is not int or event[k] < 1 for k in ("sequence", "count")): return False
    return all(type(event[k]) in (int, float) and math.isfinite(event[k]) and event[k] >= 0
               for k in ("first_unix", "last_unix"))


class AuditJournal:
    def __init__(self, directory, owner_uid=0, now=time.time):
        self.directory = Path(directory)
        self.path = self.directory / "diagnostics.json"
        self.owner_uid = owner_uid
        self.now = now

    def _check_directory(self):
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner_uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("untrusted diagnostic directory")

    def read(self):
        self._check_directory()
        try: fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError: return {"version": 1, "events": [], "last_failure": None}
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise ValueError("untrusted diagnostic file")
            raw = source.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES: raise ValueError("oversized diagnostic journal")
        data = json.loads(raw)
        if (not isinstance(data, dict) or set(data) != {"version", "events", "last_failure"}
                or type(data["version"]) is not int or data["version"] != 1
                or not isinstance(data["events"], list) or len(data["events"]) > MAX_EVENTS
                or not all(valid_event(e) for e in data["events"])):
            raise ValueError("invalid diagnostic journal")
        failure = data["last_failure"]
        if failure is not None and (not valid_event(failure) or failure["outcome"] != "failed"):
            raise ValueError("invalid last diagnostic failure")
        if any(a["sequence"] >= b["sequence"] for a, b in zip(data["events"], data["events"][1:])):
            raise ValueError("invalid diagnostic sequence")
        return data

    def record(self, operation, stage, outcome, reason="none"):
        timestamp = self.now()
        event = {"sequence": 1, "operation": operation, "stage": stage, "outcome": outcome,
                 "reason": reason, "first_unix": timestamp, "last_unix": timestamp, "count": 1}
        if not valid_event(event): raise ValueError("non-enumerated diagnostic metadata")
        data = self.read()
        events = data["events"]
        previous = events[-1] if events else None
        same = previous and all(previous[k] == event[k] for k in ("operation", "stage", "outcome", "reason"))
        if same:
            event.update(sequence=previous["sequence"], first_unix=previous["first_unix"], count=previous["count"] + 1)
            events[-1] = event
        else:
            event["sequence"] = previous["sequence"] + 1 if previous else 1
            events.append(event)
        data["events"] = events[-MAX_EVENTS:]
        if outcome == "failed": data["last_failure"] = event.copy()
        raw = json.dumps(data, separators=(",", ":")).encode("ascii")
        if len(raw) > MAX_BYTES: raise ValueError("diagnostic journal size exceeded")
        fd, name = tempfile.mkstemp(prefix=".diagnostics-", dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(raw); output.flush(); os.fsync(output.fileno())
            os.replace(name, self.path)
            directory_fd = os.open(self.directory, os.O_RDONLY)
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
        finally:
            if os.path.exists(name): os.unlink(name)
