#!/usr/bin/env python3
"""Verify an Off-state diagnostic deployment; optionally append one private event.

No firewall writes, networking probes, policy installation or timer activation.
"""
import fcntl
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import zipfile

BASE = Path("/Library/Application Support/V2BoxGuard")
BACKEND = Path("/Library/PrivilegedHelperTools/org.v2boxkillswitch.backend")
HELPER = Path("/Library/PrivilegedHelperTools/org.v2boxkillswitch.helper")
TIMER_PLIST = Path("/Library/LaunchDaemons/org.v2boxkillswitch.firsttest.plist")
ROOT = Path(__file__).resolve().parents[1]


def run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=15, check=True)


def verify_off():
    if json.loads((BASE / "state/intent.json").read_text()) != {"version": 1, "enabled": False}:
        raise RuntimeError("intent not Off")
    if (BASE / "approved.json").exists(): raise RuntimeError("approved inventory present")
    if "Status: Disabled" not in run(["/sbin/pfctl", "-s", "info"]).stdout:
        raise RuntimeError("PF is not disabled")
    if run(["/sbin/pfctl", "-a", "com.p30arena.v2box-killswitch", "-sr"]).stdout.strip():
        raise RuntimeError("project anchor not empty")
    if TIMER_PLIST.exists():
        raise RuntimeError("trial timer startup file exists")
    timer = subprocess.run(["/bin/launchctl", "print", "system/org.v2boxkillswitch.firsttest"],
                           capture_output=True, text=True, timeout=10)
    if timer.returncode == 0 or "Could not find service" not in timer.stderr:
        raise RuntimeError("trial timer not verified unloaded")


def cdhash(path):
    run(["/usr/bin/codesign", "--verify", "--strict", str(path)])
    result = run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)])
    match = re.search(r"(?m)^CDHash=([0-9a-f]{40})$", result.stderr)
    if not match: raise RuntimeError("missing code hash")
    return match.group(1)


def main():
    if os.geteuid() != 0 or sys.argv[1:] not in (["--baseline-off"], ["--verify-off"], ["--check-journal-write-off"]):
        raise RuntimeError("root and explicit Off-state verification flag required")
    verify_off()
    if sys.argv[1] == "--baseline-off":
        status = json.loads(run([str(BACKEND), "status"]).stdout)
        if status.get("state") != "off" or status.get("can_enable") != "false":
            raise RuntimeError("baseline backend not safely Off/unconfigured")
        print(json.dumps({"baseline": "off", "pf": "disabled", "project_anchor": "empty", "trial_timer": "unloaded"}))
        return
    with zipfile.ZipFile(BACKEND) as archive:
        for source in (ROOT / "src").glob("*.py"):
            if archive.read(source.name) != source.read_bytes():
                raise RuntimeError("installed backend differs from reviewed source")
    app = BASE / "V2BoxGuard.app"
    if cdhash(app) != (BASE / "client-pin").read_text().strip():
        raise RuntimeError("client pin mismatch")
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    if info.get("GuardHelperCDHash") != cdhash(HELPER):
        raise RuntimeError("helper pin mismatch")
    run(["/bin/launchctl", "print", "system/org.v2boxkillswitch.helper"])
    checked_write = sys.argv[1] == "--check-journal-write-off"
    if checked_write:
        sys.path.insert(0, str(BACKEND))
        from audit import AuditJournal
        from runtime import trusted_directory
        trusted_directory(BASE / "state")
        fd = os.open(BASE / "state/runtime.lock", os.O_WRONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "w") as outer:
            fcntl.flock(outer, fcntl.LOCK_EX)
            verify_off()
            audit = AuditJournal(BASE / "state")
            audit.record("backend", "diagnostic_preflight", "ok")
            if audit.read()["events"][-1]["stage"] != "diagnostic_preflight":
                raise RuntimeError("journal read-back failed")
    status = json.loads(run([str(BACKEND), "status"]).stdout)
    if (status.get("state") != "off" or status.get("can_enable") != "false"
            or status.get("diagnostic_history") != "available"
            or status.get("diagnostic_capability") != "backend_and_trial_timer_v1"):
        raise RuntimeError("unexpected backend diagnostic status")
    verify_off()
    print(json.dumps({"protection": "off", "pf": "disabled", "project_anchor": "empty",
                      "can_enable": False, "trial_timer": "unloaded", "approved_inventory": "absent",
                      "backend_source_bytes": "verified", "mutual_code_pins": "verified",
                      "diagnostic_history": "available", "journal_write_readback": checked_write}))


if __name__ == "__main__":
    try: main()
    except Exception as error:
        print("Off-state verification stopped:", type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
