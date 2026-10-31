#!/usr/bin/env python3
"""Remove only an OFF-state helper test installation. Never disables/flushes PF."""
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys

BASE = Path("/Library/Application Support/V2BoxGuard")
FILES = [Path("/Library/LaunchDaemons/org.v2boxkillswitch.helper.plist"),
         Path("/Library/PrivilegedHelperTools/org.v2boxkillswitch.helper"),
         Path("/Library/PrivilegedHelperTools/org.v2boxkillswitch.backend")]


def run(args):
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=15)


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ["--remove-off-install"]:
        raise RuntimeError("root and explicit --remove-off-install required")
    info = BASE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError("untrusted deployment directory")
    if (BASE / "approved.json").exists():
        raise RuntimeError("configured installation: use reviewed full uninstall instead")
    intent = json.loads((BASE / "state/intent.json").read_text())
    if intent != {"version": 1, "enabled": False}:
        raise RuntimeError("intent is not OFF; refusing to remove enforcement controls")
    anchor = run(["/sbin/pfctl", "-a", "com.p30arena.v2box-killswitch", "-sr"])
    if anchor.stdout.strip():
        raise RuntimeError("project PF rules still loaded; refusing to orphan them")
    # Stop the test helper. Do not touch any legacy or unrelated launchd jobs.
    run(["/bin/launchctl", "bootout", "system/org.v2boxkillswitch.helper"])
    right = run(["/usr/bin/security", "authorizationdb", "read", "org.v2boxkillswitch.manage"])
    definition = plistlib.loads(right.stdout.encode())
    legacy = definition.get("class") == "rule" and definition.get("rule") == ["authenticate-admin"]
    current = (definition.get("class") == "user" and definition.get("group") == "admin"
               and definition.get("authenticate-user") is True and definition.get("allow-root") is False
               and definition.get("shared") is False and definition.get("timeout") == 60)
    if (definition.get("comment") != "Authorize a V2Box Guard protection change"
            or not (legacy or current)):
        raise RuntimeError("management right changed; service stopped, manual review required")
    run(["/usr/bin/security", "authorizationdb", "remove", "org.v2boxkillswitch.manage"])
    for path in FILES:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
            raise RuntimeError("unexpected installed file; refusing deletion")
    for path in FILES: path.unlink()
    shutil.rmtree(BASE)
    print("Removed OFF-state test helper. PF enable state and rules were not modified.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("Off-state removal stopped:", error, file=sys.stderr)
        raise SystemExit(1)
