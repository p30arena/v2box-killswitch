"""Serialized controller core; no system calls to PF or launchd.

An OS-specific backend is deliberately injected. No operational backend is
shipped yet. State directory must be private, root-owned in a future service.
The unprivileged UI must never have write access to it.
"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import tempfile

from policy import compile_policy


class ControllerError(RuntimeError):
    pass


class StateStore:
    def __init__(self, directory):
        self.directory = Path(directory)

    @contextlib.contextmanager
    def locked(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (self.directory / "lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def read(self):
        path = self.directory / "intent.json"
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text())
        except (ValueError, OSError) as exc:
            raise ControllerError("cannot read persisted intent; refusing automatic changes") from exc
        if not isinstance(data, dict) or set(data) != {"version", "enabled"} or data["version"] != 1 or type(data["enabled"]) is not bool:
            raise ControllerError("invalid persisted intent; refusing automatic changes")
        return data["enabled"]

    def write(self, enabled):
        fd, name = tempfile.mkstemp(prefix="intent-", dir=self.directory)
        try:
            with os.fdopen(fd, "w") as output:
                json.dump({"version": 1, "enabled": enabled}, output)
                output.flush()
                os.fsync(output.fileno())
            os.replace(name, self.directory / "intent.json")
            directory_fd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(name):
                os.unlink(name)


class Controller:
    """Backend contract:

    snapshot() -> {pf_enabled: bool, anchor_active: bool}
      Inspect actual kernel state, including reachability of the anchor.
    replace(rules): atomic syntax-validated replacement of OUR anchor only.
    acquire(): idempotently acquire/persist OUR enable token; no borrowed token.
    remove(): remove OUR filtering only; no global flush or unrelated state kill.
    release(): release OUR persisted token only, if any; never call pfctl -d.

    OS backend must independently validate global anchor ordering and preexisting
    states. Kernel verification failures must raise rather than claim success.
    """
    def __init__(self, store, backend):
        self.store = store
        self.backend = backend

    def _status(self):
        wanted = self.store.read()
        actual = self.backend.snapshot()
        active = actual["anchor_active"] and actual["pf_enabled"]
        if wanted:
            state = "on" if active else "error"
        else:
            # An inactive PF with our rules still installed is not a completed
            # disable: another owner might enable PF later.
            state = "error" if actual["anchor_active"] else "off"
        return {"state": state, "requested_enabled": wanted, **actual,
                "vpn_health": "unverified"}

    def status(self):
        with self.store.locked():
            return self._status()

    def enable(self, config):
        rules = compile_policy(config)  # reject input before recording intent
        with self.store.locked():
            self.store.write(True)
            self.backend.replace(rules)
            self.backend.acquire()
            status = self._status()
            if status["state"] != "on":
                raise ControllerError("enforcement could not be verified")
            return status

    def disable(self):
        with self.store.locked():
            # Persist FIRST: refresh/restart must never undo this user's choice.
            self.store.write(False)
            self.backend.remove()
            self.backend.release()
            status = self._status()
            if status["state"] != "off":
                raise ControllerError("blocking anchor removal could not be verified")
            return status

    def refresh(self, config):
        with self.store.locked():
            if not self.store.read():
                # No acquire, replacement, or re-enable when explicitly disabled.
                return self._status()
            rules = compile_policy(config)
            self.backend.replace(rules)
            self.backend.acquire()
            return self._status()
