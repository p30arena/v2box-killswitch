#!/usr/bin/env python3
"""Archive only the first trial's policy while OFF. Never changes PF rules."""
import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

BASE = Path("/Library/Application Support/V2BoxGuard")


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ["--retire-off-trial"]:
        raise RuntimeError("root and explicit --retire-off-trial required")
    fd = os.open(BASE / "state/runtime.lock", os.O_WRONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if json.loads((BASE / "state/intent.json").read_text()) != {"version": 1, "enabled": False}:
            raise RuntimeError("protection is not OFF")
        for args, predicate in [
            (["/sbin/pfctl", "-s", "info"], lambda text: "Status: Disabled" in text),
            (["/sbin/pfctl", "-a", "com.p30arena.v2box-killswitch", "-sr"], lambda text: not text.strip()),
        ]:
            result = subprocess.run(args, text=True, capture_output=True, timeout=8, check=True)
            if not predicate(result.stdout): raise RuntimeError("unexpected PF state; refusing archive")
        policy = BASE / "approved.json"
        if not policy.exists():
            print("No approved trial policy to archive.")
            return
        info = policy.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise RuntimeError("untrusted trial policy file")
        if json.loads(policy.read_text()).get("profile") != "first-reviewed-local-test":
            raise RuntimeError("not the first-test policy; refusing archive")
        archive = BASE / "first-test" / ("retired-approved-" + str(time.time_ns()) + ".json")
        os.rename(policy, archive)
        print("Archived first-test policy privately. No PF change; Enable unavailable until new approval.")


if __name__ == "__main__":
    try: main()
    except Exception as error:
        print("Off-trial archive stopped:", error, file=sys.stderr)
        raise SystemExit(1)
