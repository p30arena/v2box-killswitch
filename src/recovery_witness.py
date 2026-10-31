"""Source-only durable pre-EXEC witness. No runner, PID signalling or deployment.

Caller validates ancestors and holds the shared transaction throughout native
staging, witness persistence, EXEC and completion. Data are not capabilities or
caller-authentication primitives. Only trusted native/kernel observations belong
here; do not deserialize a client's claimed completion into this interface.
"""
import os
import re
from controller import ControllerError
from recovery_broker import RecoveryBroker
from recovery_store import PendingCommandStore, _MISSING, pending_value


def process_identity(value):
    if (not isinstance(value, dict) or set(value) != {"pid", "birth_seconds", "birth_microseconds"}
            or type(value["pid"]) is not int or not 1 <= value["pid"] <= (1 << 31) - 1
            or type(value["birth_seconds"]) is not int or not 1 <= value["birth_seconds"] < (1 << 63)
            or type(value["birth_microseconds"]) is not int or not 0 <= value["birth_microseconds"] < 1_000_000):
        raise ControllerError("invalid observed process identity")
    return dict(value)


def grant_identity(value):
    if not isinstance(value, dict) or set(value) != {"ticket", "uid", "worker", "child"}:
        raise ControllerError("invalid recovery witness identity")
    identity = pending_value({"ticket": value["ticket"], "uid": value["uid"]})
    identity.update(worker=process_identity(value["worker"]), child=process_identity(value["child"]))
    if identity["worker"]["pid"] == identity["child"]["pid"]:
        raise ControllerError("worker and child must be distinct")
    return identity


class _WitnessFile(PendingCommandStore):
    # Reuse ONLY the fd-relative private-file transport, not pending semantics.
    NAME = "recovery-child-witness.json"
    TEMP_PREFIX = ".recovery-child-witness-"


class ChildWitnessStore:
    def __init__(self, directory, boot_id, expected_uid=0):
        self._file = _WitnessFile(directory, boot_id, expected_uid)
        self.boot_id = boot_id

    def _read(self, fd):
        record = self._file._read_record(fd)
        if record is _MISSING: return None
        if (not isinstance(record, dict)
                or set(record) != {"version", "boot_id", "ticket", "uid", "worker", "child", "phase", "exit_code"}
                or type(record["version"]) is not int or record["version"] != 1
                or not isinstance(record["boot_id"], str)
                or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", record["boot_id"])):
            raise ControllerError("invalid recovery child witness")
        grant_identity({key: record[key] for key in ("ticket", "uid", "worker", "child")})
        if record["phase"] == "grant_recorded":
            if record["exit_code"] is not None: raise ControllerError("unexecuted witness has exit code")
            if record["boot_id"] != self.boot_id:
                raise ControllerError("unresolved child witness belongs to another boot")
        elif record["phase"] == "completed":
            self._exit_code(record["exit_code"])
        else: raise ControllerError("unknown child witness phase")
        return record

    @staticmethod
    def _exit_code(value):
        if type(value) is not int or not -127 <= value <= 255:
            raise ControllerError("invalid supervised exit code")

    def read(self):
        fd = self._file._directory()
        try: return self._read(fd)
        finally: os.close(fd)

    def record_grant(self, value):
        identity = grant_identity(value)
        record = dict(identity, version=1, boot_id=self.boot_id, phase="grant_recorded", exit_code=None)
        fd = self._file._directory()
        try:
            previous = self._read(fd)
            if previous is not None:
                if previous["phase"] == "grant_recorded" and previous != record:
                    raise ControllerError("unresolved child witness cannot be overwritten")
                if previous["phase"] == "completed" and previous["ticket"] == identity["ticket"]:
                    raise ControllerError("completed child ticket cannot be reused")
            # Even an identical retry must durably commit, not infer an earlier
            # uncertain directory fsync succeeded merely because data are visible.
            self._file._replace_record(fd, record)
        finally: os.close(fd)
        return record

    def complete(self, value, exit_code):
        identity = grant_identity(value)
        self._exit_code(exit_code)
        fd = self._file._directory()
        try:
            previous = self._read(fd)
            if previous is None or any(previous[key] != item for key, item in identity.items()):
                raise ControllerError("completion does not match witnessed child")
            if previous["phase"] == "completed" and previous["exit_code"] != exit_code:
                raise ControllerError("completion cannot change recorded exit status")
            # An old-boot completed record is history, not current completion proof.
            if previous["boot_id"] != self.boot_id:
                raise ControllerError("completion belongs to another boot")
            record = dict(previous, phase="completed", exit_code=exit_code)
            self._file._replace_record(fd, record)
        finally: os.close(fd)
        return record


class WitnessGate:
    """Internal parent ordering only, NOT authentication or a native transport.

    authorize() must independently re-read exact enforcement/intent/console/epoch
    context, returning the actual bool True. Native worker/child identities must
    already be independently kernel-validated through the trusted native bridge.
    The caller holds the broker transaction; callbacks/identities are not IPC data.
    """
    def __init__(self, pending, witness, authorize):
        if pending.boot_id != witness.boot_id:
            raise ControllerError("pending and witness boot identities differ")
        self.pending, self.witness, self.authorize = pending, witness, authorize

    def _eligible(self):
        if self.authorize() is not True:
            raise ControllerError("fresh recovery authorization unavailable")

    def grant(self, value):
        identity = grant_identity(value)
        expected = {key: identity[key] for key in ("ticket", "uid")}
        if self.pending.read() != expected:
            raise ControllerError("no matching durable pending ticket")
        self._eligible()
        record = self.witness.record_grant(identity)
        if self.witness.read() != record or self.pending.read() != expected:
            raise ControllerError("recovery witness read-back changed")
        self._eligible()
        # No caller should send EXEC after any persistence/read-back/check error.
        return ("EXEC " + identity["ticket"] + "\n").encode("ascii")

    def finish(self, value, completion):
        # Trusted supervised termination ONLY. Persist proof before the broker
        # clears its fence. The broker remains the sole owner of pending clear;
        # this method is used inside execute_and_reap before returning Completion.
        identity = grant_identity(value)
        expected = {key: identity[key] for key in ("ticket", "uid")}
        if not RecoveryBroker.complete(completion, identity["ticket"], identity["uid"]):
            raise ControllerError("matching supervised termination proof required")
        if self.pending.read() != expected:
            raise ControllerError("completion has no matching pending ticket")
        record = self.witness.complete(identity, completion.exit_code)
        if self.witness.read() != record:
            raise ControllerError("completion witness read-back changed")
        return completion
