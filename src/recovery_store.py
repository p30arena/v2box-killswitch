"""Private boot-bound pending-command fence. No execution or default deployment.

The caller supplies trusted boot identity, validates ancestor directories and
holds the SAME cross-process transaction as every intent writer. This store is
not a mutex. It is distinct from PF-token ownership and bounded diagnostic logs.
"""
import json
import os
from pathlib import Path
import re
import stat
import uuid

from controller import ControllerError

MAX_BYTES = 2048
MAX_UID = (1 << 32) - 2


def pending_value(value):
    if (not isinstance(value, dict) or set(value) != {"ticket", "uid"}
            or not isinstance(value["ticket"], str)
            or not re.fullmatch(r"[a-f0-9]{32}", value["ticket"])
            or type(value["uid"]) is not int or not 1 <= value["uid"] <= MAX_UID):
        raise ControllerError("invalid pending recovery identity")
    return {"ticket": value["ticket"], "uid": value["uid"]}


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ControllerError("duplicate recovery record field")
        result[key] = value
    return result


class PendingCommandStore:
    NAME = "recovery-pending.json"

    def __init__(self, directory, boot_id, expected_uid=0):
        if not isinstance(boot_id, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", boot_id):
            raise ControllerError("invalid trusted boot identity")
        if type(expected_uid) is not int or not 0 <= expected_uid <= MAX_UID:
            raise ControllerError("invalid expected directory owner")
        self.directory = Path(directory)
        self.boot_id = boot_id
        self.expected_uid = expected_uid

    def _directory(self):
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if info.st_uid != self.expected_uid or stat.S_IMODE(info.st_mode) != 0o700:
                raise ControllerError("recovery directory must have trusted ownership and mode 0700")
        except Exception:
            os.close(fd)
            raise
        return fd

    def _read(self, directory_fd):
        try:
            fd = os.open(self.NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != self.expected_uid or stat.S_IMODE(info.st_mode) != 0o600):
                raise ControllerError("unsafe recovery pending file")
            payload = source.read(MAX_BYTES + 1)
        if len(payload) > MAX_BYTES: raise ControllerError("oversized recovery pending record")
        try: record = json.loads(payload, object_pairs_hook=unique_keys)
        except (ValueError, UnicodeError) as error:
            raise ControllerError("corrupt recovery pending record") from error
        if (not isinstance(record, dict) or set(record) != {"version", "boot_id", "pending"}
                or type(record["version"]) is not int or record["version"] != 1
                or not isinstance(record["boot_id"], str)
                or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", record["boot_id"])):
            raise ControllerError("invalid recovery pending record")
        pending = None if record["pending"] is None else pending_value(record["pending"])
        if pending is not None and record["boot_id"] != self.boot_id:
            # Never silently reinterpret, overwrite or clear an unresolved fence.
            raise ControllerError("recovery record belongs to another boot; reconciliation required")
        # An explicitly cleared record is not a fence, even after a boot change.
        # Reading it has no write side effects and proves nothing about PF/boot.
        return pending

    def read(self):
        fd = self._directory()
        try: return self._read(fd)
        finally: os.close(fd)

    def _replace(self, directory_fd, pending):
        temporary = ".recovery-pending-" + uuid.uuid4().hex
        created = False
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
            created = True
            with os.fdopen(fd, "w") as output:
                os.fchmod(output.fileno(), 0o600)
                json.dump({"version": 1, "boot_id": self.boot_id, "pending": pending},
                          output, separators=(",", ":"))
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.NAME, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            if created:
                try: os.unlink(temporary, dir_fd=directory_fd)
                except FileNotFoundError: pass

    def write(self, value):
        value = pending_value(value)  # Unconditional clearing is not supported.
        fd = self._directory()
        try:
            previous = self._read(fd)
            if previous is not None and previous != value:
                raise ControllerError("unresolved recovery ticket cannot be overwritten")
            self._replace(fd, value)
        finally: os.close(fd)

    def clear(self, ticket, uid):
        expected = pending_value({"ticket": ticket, "uid": uid})
        fd = self._directory()
        try:
            if self._read(fd) != expected:
                raise ControllerError("recovery completion does not match pending identity")
            # Preserve an atomic, boot-bound cleared record rather than unlinking.
            self._replace(fd, None)
        finally: os.close(fd)
