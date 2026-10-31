#!/usr/bin/env python3
"""Remove the one-shot test timer only, while protection is OFF. No PF writes."""
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import time

BASE = Path("/Library/Application Support/V2BoxGuard")
PLIST = Path("/Library/LaunchDaemons/org.v2boxkillswitch.firsttest.plist")
if os.geteuid() != 0 or sys.argv[1:] != ["--disarm-off-test"]: raise SystemExit(1)
if json.loads((BASE / "state/intent.json").read_text()) != {"version": 1, "enabled": False}:
    raise SystemExit("protection is not off; refusing timer removal")
if PLIST.exists() and plistlib.loads(PLIST.read_bytes()).get("Label") != "org.v2boxkillswitch.firsttest":
    raise SystemExit("unexpected timer definition")
subprocess.run(["/bin/launchctl", "bootout", "system/org.v2boxkillswitch.firsttest"], capture_output=True)
state = subprocess.run(["/bin/launchctl", "print", "system/org.v2boxkillswitch.firsttest"], capture_output=True, text=True)
if state.returncode == 0 or "Could not find service" not in state.stderr:
    raise SystemExit("could not verify timer unloaded")
if PLIST.exists():
    archive = BASE / "first-test" / ("disarmed-timer-" + str(time.time_ns()) + ".plist")
    shutil.copyfile(PLIST, archive)
    archive.chmod(0o600)
    PLIST.unlink()
print("One-shot timer unloaded and startup file removed. No firewall changes.")
