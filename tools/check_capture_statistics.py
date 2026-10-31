#!/usr/bin/env python3
"""Probe tcpdump's statistic signals only. No probes or firewall changes."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

BASE = Path("/Library/Application Support/V2BoxGuard/first-test")
if os.geteuid() != 0 or sys.argv[1:] != ["--check-only"]: raise SystemExit(1)
device = json.loads((BASE / "snapshot.json").read_text())["physical"][0]
if not re.fullmatch(r"en[0-9]+", device): raise SystemExit("invalid capture interface")
# Administrator-launched commands may inherit SIGINT/SIGTERM/SIGINFO blocked.
# Clear only this diagnostic thread's mask before spawning the capture child.
signal.pthread_sigmask(signal.SIG_SETMASK, [])
proc = subprocess.Popen(["/usr/sbin/tcpdump", "-n", "-l", "-q", "-s", "96", "-i", device, "host 1.1.1.1"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    time.sleep(1)
    proc.send_signal(signal.SIGINFO)
    time.sleep(1)
    proc.send_signal(signal.SIGINT)
    out, err = proc.communicate(timeout=4)
    stats = [x for x in (out + "\n" + err).splitlines() if re.search(r"packet|drop|capture|listening", x, re.I)]
    result = {"exit_code": proc.returncode, "statistic_lines": stats}
    (BASE / "capture-statistics-diagnostic.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result))
finally:
    if proc.poll() is None: proc.kill(); proc.wait()
