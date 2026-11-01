#!/usr/bin/env python3
"""Explicit per-user tracker installation. Never root, PF, VPN commands or helper changes."""
import argparse
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import time

LABEL = "org.v2boxkillswitch.reconnecttracker"
REPO = Path(__file__).resolve().parents[1]


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=20)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-start-at-login", action="store_true")
    parser.add_argument("--archive-old-watchdog", action="store_true",
                        help="Preserve/unload the known old user reconnect agent to avoid competing trackers")
    args = parser.parse_args()
    if not args.install_start_at_login:
        parser.error("Installation/start requires explicit --install-start-at-login")
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        parser.error("Run as your normal logged-in user, never sudo")
    home = Path.home()
    source = REPO / ".build/V2Box Reconnect Tracker.app"
    destination = home / "Applications/V2Box Reconnect Tracker.app"
    agents = home / "Library/LaunchAgents"
    agent = agents / (LABEL + ".plist")
    old_agent = agents / "com.ali.v2box-vpn-guard.plist"
    if old_agent.exists() and not args.archive_old_watchdog:
        parser.error("Old user watchdog exists; inspect it, then explicitly pass --archive-old-watchdog")
    if destination.exists() or destination.is_symlink() or agent.exists() or agent.is_symlink():
        parser.error("Tracker already installed or destination occupied; refusing a blind replacement")
    run("/usr/bin/codesign", "--verify", "--strict", str(source))
    with (source / "Contents/Info.plist").open("rb") as f:
        if plistlib.load(f).get("CFBundleIdentifier") != LABEL:
            parser.error("Unexpected build bundle identity")
    # Do not terminate a manually running watcher or replace its live executable.
    running = run("/usr/bin/pgrep", "-u", str(os.getuid()), "-f", str(source / "Contents/MacOS/V2BoxReconnectTracker"), check=False)
    if running.returncode == 0:
        parser.error("Build-directory tracker is running; quit it before installation")
    destination.parent.mkdir(parents=True, exist_ok=True)
    agents.mkdir(parents=True, exist_ok=True)
    backup = home / "Library/Application Support/V2BoxReconnectTracker" / ("install-backup-" + str(time.time_ns()))
    backup.mkdir(parents=True, mode=0o700)
    if old_agent.exists():
        with old_agent.open("rb") as f:
            old_label = plistlib.load(f).get("Label")
        if old_label != "com.ali.v2box-vpn-guard":
            parser.error("Unexpected old watchdog label; left untouched")
        run("/bin/launchctl", "bootout", "gui/" + str(os.getuid()) + "/" + old_label, check=False)
        old_agent.rename(backup / old_agent.name)
    shutil.copytree(source, destination, symlinks=False)
    configuration = {"Label": LABEL,
                     "ProgramArguments": [str(destination / "Contents/MacOS/V2BoxReconnectTracker")],
                     "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False},
                     "ThrottleInterval": 5, "LimitLoadToSessionType": "Aqua",
                     "ProcessType": "Interactive"}
    with tempfile.NamedTemporaryFile(dir=agents, delete=False) as f:
        plistlib.dump(configuration, f); f.flush(); os.fsync(f.fileno()); temporary = f.name
    os.replace(temporary, agent)
    try:
        run("/bin/launchctl", "bootstrap", "gui/" + str(os.getuid()), str(agent))
        run("/bin/launchctl", "print", "gui/" + str(os.getuid()) + "/" + LABEL)
    except Exception:
        # Leave a clear failed install, not a claim of active monitoring. Do not
        # restore/restart the old watchdog or touch a running VPN on failure.
        raise RuntimeError("Tracker startup failed; installation remains for inspection, VPN untouched")
    print("Installed and started user tracker; automatic reconnect defaults On unless explicitly paused.")
    print("Starts at login; restarts after abnormal exit. No PF/helper/VPN-stop operations performed.")
    print("NOT a kill switch: IP exposure remains possible during an outage.")


if __name__ == "__main__":
    main()
