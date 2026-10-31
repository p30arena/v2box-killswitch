"""Boot-bound durable PF-token journal. Does not inspect or operate PF.

Caller supplies a trusted boot identity obtained by a future privileged service,
not from an IPC client, and holds the controller's cross-process lock.
"""
import json
import os
from pathlib import Path
import re
import stat
import uuid

from controller import ControllerError


class TokenStore:
    NAME = "pf-token.json"

    def __init__(self, directory, boot_id, expected_uid=0):
        self.directory = Path(directory)
        if not isinstance(boot_id, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", boot_id):
            raise ControllerError("invalid trusted boot identity")
        self.boot_id = boot_id
        self.expected_uid = expected_uid

    def _directory(self):
        # Do not silently create privileged state in a caller-supplied path.
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if info.st_uid != self.expected_uid or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(fd)
            raise ControllerError("token directory must have trusted ownership and mode 0700")
        return fd

    def read(self):
        directory_fd = self._directory()
        try:
            try:
                fd = os.open(self.NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            except FileNotFoundError:
                return None
            with os.fdopen(fd, "rb") as source:
                info = os.fstat(source.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                        info.st_uid != self.expected_uid or stat.S_IMODE(info.st_mode) != 0o600):
                    raise ControllerError("unsafe PF token file")
                payload = source.read(4097)
            if len(payload) > 4096:
                raise ControllerError("oversized PF token record")
            try:
                record = json.loads(payload)
            except (ValueError, UnicodeError) as exc:
                raise ControllerError("corrupt PF token record; explicit reconciliation required") from exc
            if (not isinstance(record, dict) or set(record) != {"version", "boot_id", "token"}
                    or type(record["version"]) is not int or record["version"] != 1):
                raise ControllerError("invalid PF token record")
            if record["boot_id"] != self.boot_id:
                raise ControllerError("PF token belongs to another boot; explicit reconciliation required")
            token = record["token"]
            if token is not None and (not isinstance(token, str) or
                                      (token != "pending" and not re.fullmatch(r"[0-9]{1,20}", token))):
                raise ControllerError("invalid PF token value")
            return token
        finally:
            os.close(directory_fd)

    def write(self, token):
        if token is not None and (not isinstance(token, str) or
                                  (token != "pending" and not re.fullmatch(r"[0-9]{1,20}", token))):
            raise ControllerError("invalid PF token value")
        directory_fd = self._directory()
        temporary = ".pf-token-" + uuid.uuid4().hex
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
            try:
                with os.fdopen(fd, "w") as output:
                    os.fchmod(output.fileno(), 0o600)
                    json.dump({"version": 1, "boot_id": self.boot_id, "token": token}, output)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, self.NAME, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                os.fsync(directory_fd)
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
        finally:
            os.close(directory_fd)
