#!/usr/bin/env python3
"""Independent first-test safety timer. NEVER disables PF or permits direct egress.

Deployed only by an explicitly approved test. Waits for activation, then leaves
quarantine + persisted disabled intent if the operator has not confirmed the test.
"""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

BASE = Path("/Library/Application Support/V2BoxGuard")
TEST = BASE / "first-test"


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ["--watch"]:
        return 1
    sys.path.insert(0, "/Library/PrivilegedHelperTools/org.v2boxkillswitch.backend")
    from controller import StateStore
    store = StateStore(BASE / "state")
    # No activation within 15 minutes: exit WITHOUT changing any rule or intent.
    waiting_until = time.monotonic() + 900
    while time.monotonic() < waiting_until:
        if (TEST / "confirmed").exists(): return 0
        with store.locked(): enabled = store.read()
        if enabled: break
        time.sleep(1)
    else:
        return 0
    (TEST / "activation-observed.json").write_text(json.dumps({"unix_time": time.time(), "fallback_after_seconds": 600}))
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        if (TEST / "confirmed").exists(): return 0
        with store.locked(): enabled = store.read()
        if not enabled: return 0
        time.sleep(1)
    # Same outer lock as real backend; no refresh can race persisted Disable.
    fd = os.open(BASE / "state/runtime.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as outer:
        fcntl.flock(outer, fcntl.LOCK_EX)
        with store.locked():
            if (TEST / "confirmed").exists() or not store.read(): return 0
            policy = TEST / "quarantine.pf"
            subprocess.run(["/sbin/pfctl", "-n", "-a", "com.p30arena.v2box-killswitch", "-f", str(policy)],
                           capture_output=True, check=True, timeout=8)
            store.write(False)
            subprocess.run(["/sbin/pfctl", "-a", "com.p30arena.v2box-killswitch", "-f", str(policy)],
                           capture_output=True, check=True, timeout=8)
            (TEST / "fallback-applied").write_text("Quarantine retained; explicit menu Disable is needed to allow direct access.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
