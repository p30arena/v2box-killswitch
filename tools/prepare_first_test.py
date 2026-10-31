#!/usr/bin/env python3
"""Prepare, but NEVER enable, a first controlled firewall test. Explicit root only."""
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BASE = Path("/Library/Application Support/V2BoxGuard")
TEST = BASE / "first-test"
PLIST = Path("/Library/LaunchDaemons/org.v2boxkillswitch.firsttest.plist")


def command(args, input=None):
    return subprocess.run(args, input=input, capture_output=True, text=True, timeout=30, check=True)


def atomic(path, text, mode):
    fd, temporary = tempfile.mkstemp(prefix=".v2box-stage-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            os.fchmod(output.fileno(), mode)
            output.write(text); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ["--prepare-only"]:
        raise RuntimeError("root and --prepare-only required")
    if (BASE / "approved.json").exists() or TEST.exists() or PLIST.exists():
        raise RuntimeError("previous policy/test exists; refusing overwrite")
    intent = json.loads((BASE / "state/intent.json").read_text())
    if intent != {"version": 1, "enabled": False}: raise RuntimeError("intent must be OFF")
    result = command(["/usr/bin/python3", "-I", str(ROOT / "tools/inspect_before_activation.py")])
    facts = json.loads(result.stdout)
    if facts["pf_enabled"] or facts["existing_state_count"] or facts["skip_flags_present"]:
        raise RuntimeError("unexpected PF baseline")
    backup = Path(facts["private_backup"])
    discovery = json.loads((backup / "discovery.json").read_text())
    if discovery["vpn_status"] != "Connected" or not discovery["matching_transport_peers"]:
        raise RuntimeError("no matching live transport for currently connected VPN")
    # Refuse root filter rules we cannot preserve safely. No global flush.
    raw_baseline = (backup / "pf-root.txt").read_text()
    baseline_rules = "\n".join(x.strip() for x in raw_baseline.splitlines()
                               if x.strip() and not x.strip().startswith(("scrub ", "scrub-anchor ", "no scrub ")))
    if baseline_rules not in ('', 'anchor "com.apple/*" all', 'anchor "/*" all'):
        raise RuntimeError("non-default root filters need separate integration review")
    recursive = command(["/sbin/pfctl", "-a", "*", "-sr"]).stdout
    atomic(backup / "recursive-filters.txt", recursive, 0o600)
    # Detached old anchors are backed up but never attached/deleted. Only the
    # Apple subtree will be referenced by the proposed global config.
    apple = command(["/sbin/pfctl", "-a", "com.apple", "-sr"]).stdout
    apple += command(["/sbin/pfctl", "-a", "com.apple/*", "-sr"]).stdout
    atomic(backup / "apple-filters.txt", apple, 0o600)
    if any(line.strip().startswith(("pass ", "block ", "match ")) for line in apple.splitlines()):
        raise RuntimeError("populated Apple filters require separate integration review")
    sys.path.insert(0, "/Library/PrivilegedHelperTools/org.v2boxkillswitch.backend")
    from runtime import Runtime, run
    from policy import compile_policy, compile_quarantine
    from endpoints import approved_config
    from health import HealthProbe
    config = {"experimental_ack": "I accept experimental PF behavior",
              "service_uuid": discovery["service_uuid"], "service_name": discovery["service_name"],
              "profile": "first-reviewed-local-test", "inventory": {"version": 1, "profiles": {
                  "first-reviewed-local-test": {"revision": str(int(time.time())),
                      "expires_at": int(time.time()) + 86400,
                      "endpoints": discovery["matching_transport_peers"]}}}}
    runtime = Runtime(None, run, lambda: config)
    runtime.preflight()
    base = runtime.snapshot(config)
    if not base["tunnel"]: raise RuntimeError("connected V2Box tunnel unavailable")
    policy = compile_policy(approved_config(base, config["inventory"], config["profile"], time.time()))
    quarantine = compile_quarantine(base)
    command(["/sbin/pfctl", "-n", "-a", "com.p30arena.v2box-killswitch", "-f", "-"], input=policy)
    command(["/sbin/pfctl", "-n", "-a", "com.p30arena.v2box-killswitch", "-f", "-"], input=quarantine)
    def probe_run(args, timeout, env):
        return subprocess.run(args, timeout=timeout, env=env, capture_output=True, text=True)
    probe = HealthProbe("https://1.1.1.1/cdn-cgi/trace", "1.1.1.1", 200, probe_run,
                        lambda tunnel: runtime.snapshot(config)["tunnel"] == tunnel)
    health = probe.check(base["tunnel"])
    if health.health != "usable": raise RuntimeError("baseline tunnel probe failed: " + health.reason)
    old = Path("/etc/pf.conf").read_text()
    gate = 'anchor "com.p30arena.v2box-killswitch" quick\n'
    target = 'anchor "com.apple/*"\n'
    lines = old.splitlines(keepends=True)
    matches = [i for i, line in enumerate(lines) if line == target]
    if len(matches) != 1 or gate in old:
        raise RuntimeError("unexpected PF config; manual integration needed")
    lines.insert(matches[0], gate)
    proposed = "".join(lines)
    command(["/sbin/pfctl", "-n", "-f", "-"], input=proposed)
    # Stage all test artifacts, still OFF and with no approved policy installed.
    TEST.mkdir(mode=0o700)
    atomic(TEST / "quarantine.pf", quarantine, 0o600)
    atomic(TEST / "active.pf", policy, 0o600)
    atomic(TEST / "snapshot.json", json.dumps(base), 0o600)
    atomic(TEST / "backup-path", str(backup), 0o600)
    shutil.copyfile(ROOT / "tools/first_test_fallback.py", TEST / "fallback.py")
    (TEST / "fallback.py").chmod(0o700)
    daemon = {"Label": "org.v2boxkillswitch.firsttest", "RunAtLoad": True,
              "ProgramArguments": ["/usr/bin/python3", "-I", str(TEST / "fallback.py"), "--watch"]}
    atomic(PLIST, plistlib.dumps(daemon).decode(), 0o644)
    changed_root = False
    armed = False
    try:
        # PF stays DISABLED. This attaches an empty gate only. All original root
        # text is backed up; any failure before activation restores it.
        atomic(Path("/etc/pf.conf"), proposed, 0o644)
        changed_root = True
        command(["/sbin/pfctl", "-f", "/etc/pf.conf"])
        if "Status: Disabled" not in command(["/sbin/pfctl", "-s", "info"]).stdout:
            raise RuntimeError("PF unexpectedly enabled; stop for manual review")
        command(["/bin/launchctl", "bootstrap", "system", str(PLIST)])
        armed = True
        time.sleep(1)
        service = command(["/bin/launchctl", "print", "system/org.v2boxkillswitch.firsttest"]).stdout
        if "state = running" not in service: raise RuntimeError("independent safety timer not running")
        # LAST: expose Enable to the app only after syntax, baseline probe and
        # independent timer are ready. Do not enable here or set intent true.
        atomic(BASE / "approved.json", json.dumps(config, indent=2), 0o600)
        status = json.loads(command(["/Library/PrivilegedHelperTools/org.v2boxkillswitch.backend", "status"]).stdout)
        if status.get("state") != "off" or status.get("can_enable") != "true":
            loaded_root = command(["/sbin/pfctl", "-sr"]).stdout
            atomic(backup / "not-ready-root.txt", loaded_root, 0o600)
            atomic(backup / "not-ready-status.json", json.dumps(status), 0o600)
            raise RuntimeError("staged backend not ready: state=" + str(status.get("state"))
                               + ", can_enable=" + str(status.get("can_enable"))
                               + ", root=" + loaded_root.strip())
        print(json.dumps({"prepared": True, "pf_enabled": False, "protection": "off",
                          "can_enable": True, "private_backup": str(backup),
                          "timer_waits_for_activation_seconds": 900,
                          "quarantine_after_activation_seconds": 180,
                          "approved_inventory_expires_in_seconds": 86400}))
    except Exception:
        # This routine NEVER enables PF. If an external actor did, do not restore
        # an empty baseline and accidentally remove protection.
        if "Status: Disabled" in command(["/sbin/pfctl", "-s", "info"]).stdout:
            (BASE / "approved.json").unlink(missing_ok=True)
            if armed:
                subprocess.run(["/bin/launchctl", "bootout", "system/org.v2boxkillswitch.firsttest"], capture_output=True)
            if changed_root:
                atomic(Path("/etc/pf.conf"), old, 0o644)
                command(["/sbin/pfctl", "-f", "/etc/pf.conf"])
        raise


if __name__ == "__main__":
    try: main()
    except Exception as error:
        print("First-test preparation stopped:", error, file=sys.stderr)
        raise SystemExit(1)
