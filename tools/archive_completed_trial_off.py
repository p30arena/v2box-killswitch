#!/usr/bin/env python3
"""Preserve a completed trial before preparing another. No PF writes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

BASE = Path("/Library/Application Support/V2BoxGuard")


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ["--archive-completed-off"]: raise RuntimeError("root and explicit flag required")
    if json.loads((BASE / "state/intent.json").read_text()) != {"version": 1, "enabled": False}: raise RuntimeError("not Off")
    if (BASE / "approved.json").exists(): raise RuntimeError("approved policy still present")
    if Path("/Library/LaunchDaemons/org.v2boxkillswitch.firsttest.plist").exists(): raise RuntimeError("timer startup file still present")
    loaded = subprocess.run(["/bin/launchctl", "print", "system/org.v2boxkillswitch.firsttest"], capture_output=True, text=True)
    if loaded.returncode == 0 or "Could not find service" not in loaded.stderr: raise RuntimeError("timer may still be loaded")
    info = subprocess.run(["/sbin/pfctl", "-s", "info"], capture_output=True, text=True, check=True)
    if "Status: Disabled" not in info.stdout: raise RuntimeError("PF is not disabled")
    trial = BASE / "first-test"
    if not trial.exists(): print("No prior trial directory."); return
    if not (trial / "observation.json").is_file(): raise RuntimeError("prior observer completion not recorded")
    if (trial / "observer.pid").exists():
        pid = int((trial / "observer.pid").read_text())
        if pid < 2: raise RuntimeError("invalid observer PID")
        try: os.kill(pid, 0)
        except ProcessLookupError: pass
        else: raise RuntimeError("prior observer PID still exists; do not archive without review")
    destination = BASE / "state" / ("completed-trial-" + str(time.time_ns()))
    trial.rename(destination)
    print("Archived completed trial evidence privately. PF unchanged.")


if __name__ == "__main__":
    try: main()
    except Exception as error:
        print("Trial archive stopped:", error, file=sys.stderr)
        raise SystemExit(1)
