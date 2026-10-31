#!/usr/bin/env python3
"""Arm independent diagnostics while protection remains OFF. No PF changes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

BASE = Path("/Library/Application Support/V2BoxGuard")
TEST = BASE / "first-test"
ROOT = Path(__file__).resolve().parents[1]
if os.geteuid() != 0 or sys.argv[1:] != ["--arm"]: raise SystemExit(1)
if json.loads((BASE / "state/intent.json").read_text()) != {"version": 1, "enabled": False}: raise SystemExit("must be off")
if (TEST / "observer.pid").exists(): raise SystemExit("observer already armed; inspect before retry")
subprocess.run(["/bin/launchctl", "kickstart", "-k", "system/org.v2boxkillswitch.firsttest"], check=True, capture_output=True)
shutil.copyfile(ROOT / "tools/observe_first_test.py", TEST / "observer.py")
(TEST / "observer.py").chmod(0o700)
with (TEST / "observer.log").open("w") as log:
    process = subprocess.Popen(["/usr/bin/python3", "-I", str(TEST / "observer.py"), "--observe"],
                               stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
(TEST / "observer.pid").write_text(str(process.pid))
print("Safety timer restarted, independent observer armed. PF not modified. Ready for menu Enable.")
