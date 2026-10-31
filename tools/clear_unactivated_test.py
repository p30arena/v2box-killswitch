#!/usr/bin/env python3
"""Archive a FAILED, never-activated preparation. No PF changes."""
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import time

BASE = Path("/Library/Application Support/V2BoxGuard")
if os.geteuid() != 0 or sys.argv[1:] != ["--clear-unactivated"]: raise SystemExit(1)
if (BASE / "approved.json").exists(): raise SystemExit("approved policy exists; refusing cleanup")
if json.loads((BASE / "state/intent.json").read_text()) != {"version": 1, "enabled": False}: raise SystemExit("not off")
info = subprocess.run(["/sbin/pfctl", "-s", "info"], capture_output=True, text=True, check=True)
if "Status: Disabled" not in info.stdout: raise SystemExit("PF not disabled; refusing cleanup")
plist = Path("/Library/LaunchDaemons/org.v2boxkillswitch.firsttest.plist")
if plist.exists():
    if plistlib.loads(plist.read_bytes()).get("Label") != "org.v2boxkillswitch.firsttest": raise SystemExit("unexpected timer definition")
    subprocess.run(["/bin/launchctl", "bootout", "system/org.v2boxkillswitch.firsttest"], capture_output=True)
    still_loaded = subprocess.run(["/bin/launchctl", "print", "system/org.v2boxkillswitch.firsttest"], capture_output=True)
    if still_loaded.returncode == 0: raise SystemExit("timer still loaded; stop")
    plist.unlink()
test = BASE / "first-test"
if test.exists(): test.rename(BASE / "state" / ("unactivated-test-" + str(time.time_ns())))
print("Archived failed unactivated preparation. PF unchanged.")
