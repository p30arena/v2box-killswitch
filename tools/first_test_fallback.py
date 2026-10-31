#!/usr/bin/env python3
"""Independent trial timer. NEVER disables PF or permits direct egress.

Source/build only. Journal instrumentation does not change the deadline policy.
An incomplete trial still causes quarantine; do not arm another live trial yet.
"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

BASE = Path("/Library/Application Support/V2BoxGuard")
TEST = BASE / "first-test"


@contextlib.contextmanager
def runtime_lock():
    fd = os.open(BASE / "state/runtime.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as outer:
        fcntl.flock(outer, fcntl.LOCK_EX)
        yield


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ["--watch"]:
        return 1
    sys.path.insert(0, "/Library/PrivilegedHelperTools/org.v2boxkillswitch.backend")
    from audit import AuditJournal
    from controller import StateStore
    store = StateStore(BASE / "state")
    audit = AuditJournal(BASE / "state")

    def event(stage, outcome, reason="none"):
        # Caller owns runtime_lock. No exception text/native output is recorded.
        try: audit.record("trial_timer", stage, outcome, reason)
        except Exception: pass  # Diagnostic failure must not prevent quarantine.

    def finish(reason):
        # Never acquire the outer lock while holding the inner StateStore lock.
        with runtime_lock(): event("trial_wait", "ok", reason)
        return 0

    with runtime_lock(): event("trial_wait", "started")
    waiting_until = time.monotonic() + 900
    while time.monotonic() < waiting_until:
        if (TEST / "confirmed").exists(): return finish("confirmation_present")
        with store.locked(): enabled = store.read()
        if enabled: break
        time.sleep(1)
    else:
        return finish("activation_timeout")
    (TEST / "activation-observed.json").write_text(json.dumps({"unix_time": time.time(), "fallback_after_seconds": 600}))
    with runtime_lock(): event("trial_deadline", "started", "confirmation_missing")
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        if (TEST / "confirmed").exists(): return finish("confirmation_present")
        with store.locked(): enabled = store.read()
        if not enabled: return finish("disabled_intent")
        time.sleep(1)
    # Same lock order as backend. Explicit Disable and confirmation win here too.
    with runtime_lock():
        with store.locked():
            if (TEST / "confirmed").exists():
                event("trial_deadline", "ok", "confirmation_present"); return 0
            if not store.read():
                event("trial_deadline", "skipped_disabled", "disabled_intent"); return 0
            event("trial_deadline", "ok", "confirmation_missing")
            stage = "trial_syntax"
            try:
                policy = TEST / "quarantine.pf"
                event(stage, "started")
                subprocess.run(["/sbin/pfctl", "-n", "-a", "com.p30arena.v2box-killswitch", "-f", str(policy)],
                               capture_output=True, check=True, timeout=8)
                event(stage, "ok")
                stage = "trial_disable_intent"
                event(stage, "started")
                store.write(False)
                event(stage, "ok")
                stage = "trial_apply_quarantine"
                event(stage, "started")
                subprocess.run(["/sbin/pfctl", "-a", "com.p30arena.v2box-killswitch", "-f", str(policy)],
                               capture_output=True, check=True, timeout=8)
                # "ok" means command completed, NOT proof of kernel enforcement.
                event(stage, "ok")
                stage = "trial_marker"
                event(stage, "started")
                (TEST / "fallback-applied").write_text("Quarantine retained; explicit menu Disable is needed to allow direct access.\n")
                event(stage, "ok")
            except Exception:
                event(stage, "failed", "operation_failed")
                raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
