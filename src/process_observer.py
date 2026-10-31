"""Read-only macOS kernel snapshots, NOT signing attestation or signal authority.

No default execution, liveness reconciliation or 'missing PID means completed'.
Expected worker identity/parent must come from a trusted live launch, not IPC.
"""
import ctypes
from dataclasses import dataclass
import sys

from controller import ControllerError
from recovery_store import MAX_UID
from recovery_witness import process_identity

MAX_PID = (1 << 31) - 1
BSD_RUNNABLE, BSD_SLEEPING, BSD_STOPPED = 2, 3, 4  # Public Darwin sys/proc.h states.


class _BSDInfo(ctypes.Structure):
    # Public 64-bit macOS proc_bsdinfo ABI (sys/proc_info.h), not kinfo_proc.
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid", "svuid", "svgid", "reserved")]
    _fields_ += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in ("nfiles", "pgid", "pjobc", "ttyd", "tty_pgid")]
    _fields_ += [("nice", ctypes.c_int32), ("birth_seconds", ctypes.c_uint64), ("birth_microseconds", ctypes.c_uint64)]


@dataclass(frozen=True)
class ProcessSnapshot:
    pid: int
    parent_pid: int
    uid: int
    real_uid: int
    saved_uid: int
    gid: int
    real_gid: int
    saved_gid: int
    birth_seconds: int
    birth_microseconds: int
    state: int

    def identity(self):
        return process_identity({"pid": self.pid, "birth_seconds": self.birth_seconds,
                                 "birth_microseconds": self.birth_microseconds})

    def stable_key(self):
        self.identity()
        if (type(self.parent_pid) is not int or not 0 <= self.parent_pid <= MAX_PID
                or any(type(value) is not int or not 0 <= value <= MAX_UID for value in (
                    self.uid, self.real_uid, self.saved_uid, self.gid, self.real_gid, self.saved_gid))
                or type(self.state) is not int or not 1 <= self.state <= 5):
            raise ControllerError("invalid kernel process snapshot")
        return (self.pid, self.parent_pid, self.uid, self.real_uid, self.saved_uid,
                self.gid, self.real_gid, self.saved_gid, self.birth_seconds, self.birth_microseconds)


class KernelProcessObserver:
    def __init__(self, read_bsd=None):
        # Injection is for trusted tests/parent code, never an IPC request field.
        self._read = read_bsd if read_bsd is not None else self._native_reader()

    @staticmethod
    def _native_reader():
        if (sys.platform != "darwin" or ctypes.sizeof(ctypes.c_void_p) != 8
                or ctypes.sizeof(_BSDInfo) != 136 or _BSDInfo.birth_seconds.offset != 120):
            raise ControllerError("unsupported kernel process observation ABI")
        try:
            library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            query = library.proc_pidinfo
            query.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
            query.restype = ctypes.c_int
        except (OSError, AttributeError) as error:
            raise ControllerError("kernel process observation unavailable") from error
        def read(pid):
            info = _BSDInfo()
            # PROC_PIDTBSDINFO = 3, from the public macOS sys/proc_info.h.
            count = query(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
            if count != ctypes.sizeof(info):
                # Missing/denied/short/error all remain UNKNOWN, never completion.
                raise ControllerError("kernel process observation unavailable")
            return ProcessSnapshot(info.pid, info.ppid, info.uid, info.ruid, info.svuid,
                                   info.gid, info.rgid, info.svgid, info.birth_seconds,
                                   info.birth_microseconds, info.status)
        return read

    def observe(self, pid, allowed_states=None):
        if type(pid) is not int or not 1 <= pid <= MAX_PID:
            raise ControllerError("positive observed PID required")
        samples = []
        for _ in range(2):
            try: snapshot = self._read(pid)
            except Exception as error:
                raise ControllerError("kernel process observation unavailable") from error
            if not isinstance(snapshot, ProcessSnapshot) or snapshot.pid != pid:
                raise ControllerError("kernel process identity unavailable")
            snapshot.stable_key()
            if allowed_states is not None and snapshot.state not in allowed_states:
                raise ControllerError("kernel process state changed")
            samples.append(snapshot)
        if samples[0].stable_key() != samples[1].stable_key():
            raise ControllerError("kernel process identity changed")
        return samples[1]

    def verify_staged(self, worker, child, uid, primary_gid, worker_parent_pid):
        worker, child = process_identity(worker), process_identity(child)
        if (type(uid) is not int or not 1 <= uid <= MAX_UID
                or type(primary_gid) is not int or not 0 <= primary_gid <= MAX_UID
                or type(worker_parent_pid) is not int or not 1 <= worker_parent_pid <= MAX_PID
                or worker["pid"] == child["pid"]):
            raise ControllerError("invalid trusted staging expectations")
        # Bracket the child observations with worker observations. This is still
        # a consistency check, not an atomic lease or authority to send a signal.
        first = self.observe(worker["pid"], {BSD_RUNNABLE, BSD_SLEEPING})
        staged = self.observe(child["pid"], {BSD_STOPPED})
        last = self.observe(worker["pid"], {BSD_RUNNABLE, BSD_SLEEPING})
        staged_last = self.observe(child["pid"], {BSD_STOPPED})
        if (first.identity() != worker or last.stable_key() != first.stable_key()
                or staged.identity() != child or staged_last.stable_key() != staged.stable_key()
                or first.parent_pid != worker_parent_pid or staged.parent_pid != first.pid):
            raise ControllerError("staged process relationship changed")
        for snapshot in (first, staged):
            if ((snapshot.uid, snapshot.real_uid, snapshot.saved_uid) != (uid, uid, uid)
                    or (snapshot.gid, snapshot.real_gid, snapshot.saved_gid) != (primary_gid,) * 3):
                raise ControllerError("staged process credentials mismatch")
        return {"worker": first.identity(), "child": staged.identity()}
