"""Fixed READ-ONLY root-to-user launch validation. No execution defaults.

Not a VPN executor or descendant supervisor. UID/expectations must come from
trusted console/account state, never caller-supplied IPC fields.
"""
from dataclasses import dataclass
import re

MAX_ID = (1 << 32) - 2
CHECKS = {
    "effective_uid": ("/usr/bin/id", "-u"),
    "real_uid": ("/usr/bin/id", "-ru"),
    "effective_gid": ("/usr/bin/id", "-g"),
    "real_gid": ("/usr/bin/id", "-rg"),
    "groups": ("/usr/bin/id", "-G"),
    "bootstrap_uid": ("/bin/launchctl", "manageruid"),
    "session_type": ("/bin/launchctl", "managername"),
}
ENVIRONMENT = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}


@dataclass(frozen=True)
class LaunchCheck:
    verified: bool
    reason: str


def user_uid(uid):
    if type(uid) is not int or not 1 <= uid <= MAX_ID:
        raise ValueError("non-root console UID required")


def identity_argv(check, uid):
    user_uid(uid)
    if not isinstance(check, str) or check not in CHECKS:
        raise ValueError("fixed read-only identity check required")
    # asuser adopts bootstrap/audit context only. sudo drops UID/GID/groups.
    # Numeric UID is generated internally; there is no shell or caller command.
    return ["/bin/launchctl", "asuser", str(uid), "/usr/bin/sudo", "-n", "-u", "#" + str(uid), "--", *CHECKS[check]]


def numeric(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,10}", value): return None
    number = int(value)
    return number if 0 <= number <= MAX_ID else None


def check_user_launch(uid, primary_gid, allowed_groups, run):
    user_uid(uid)
    if type(primary_gid) is not int or not 0 <= primary_gid <= MAX_ID:
        raise ValueError("trusted primary group required")
    if (not isinstance(allowed_groups, (set, frozenset)) or len(allowed_groups) > 1024
            or any(type(group) is not int or not 0 <= group <= MAX_ID for group in allowed_groups)):
        raise ValueError("bounded trusted account group set required")
    groups = set(allowed_groups) | {primary_gid}
    for check in CHECKS:
        try:
            result = run(identity_argv(check, uid), timeout=4, env=ENVIRONMENT.copy())
            if result.returncode != 0: return LaunchCheck(False, "launch_unavailable")
            if not isinstance(result.stdout, str) or len(result.stdout) > 4096:
                return LaunchCheck(False, "invalid_identity_output")
            value = result.stdout.strip()
        except Exception:
            return LaunchCheck(False, "launch_unavailable")
        if check in {"effective_uid", "real_uid", "bootstrap_uid"}:
            if numeric(value) != uid: return LaunchCheck(False, "user_identity_mismatch")
        elif check in {"effective_gid", "real_gid"}:
            if numeric(value) != primary_gid: return LaunchCheck(False, "primary_group_mismatch")
        elif check == "groups":
            fields = value.split()
            if not fields or len(fields) > 1024: return LaunchCheck(False, "invalid_identity_output")
            observed = [numeric(field) for field in fields]
            if None in observed or not set(observed).issubset(groups):
                return LaunchCheck(False, "supplementary_group_mismatch")
        elif value != "Aqua":
            return LaunchCheck(False, "bootstrap_session_mismatch")
    return LaunchCheck(True, "read_only_identity_verified")
