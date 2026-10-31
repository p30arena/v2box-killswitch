#!/usr/bin/env python3
"""Explicit root installation for OFF-state IPC testing only. Never loads PF.

Not invoked by builds. Refuses existing deployments. Does not install a policy.
"""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / ".build/development-kit"
BASE = Path("/Library/Application Support/V2BoxGuard")
HELPER = Path("/Library/PrivilegedHelperTools/org.v2boxkillswitch.helper")
BACKEND = Path("/Library/PrivilegedHelperTools/org.v2boxkillswitch.backend")
DAEMON = Path("/Library/LaunchDaemons/org.v2boxkillswitch.helper.plist")
APP = BASE / "V2BoxGuard.app"


def command(args):
    return subprocess.run(args, text=True, capture_output=True, check=True, timeout=30)


def trusted_parent(path):
    current = path
    while True:
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("untrusted install directory")
        if current == current.parent: return
        current = current.parent


def copy(source, target, mode):
    shutil.copyfile(source, target)
    target.chmod(mode)
    os.chown(target, 0, 0)


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ["--install-off"]:
        raise RuntimeError("root and explicit --install-off required")
    for target in (BASE, HELPER, BACKEND, DAEMON, APP):
        if os.path.lexists(target):
            raise RuntimeError("existing deployment; refusing to overwrite: " + str(target))
    for parent in (BASE.parent, HELPER.parent, DAEMON.parent):
        trusted_parent(parent)
    for source in KIT.rglob("*"):
        if source.is_symlink(): raise RuntimeError("symlink in kit refused")
    for artifact in (KIT / "org.v2boxkillswitch.helper", KIT / "V2BoxGuard.app"):
        command(["/usr/bin/codesign", "--verify", "--strict", str(artifact)])
    pin = (KIT / "client-pin").read_text().strip()
    signature = command(["/usr/bin/codesign", "-d", "--verbose=4", str(KIT / "V2BoxGuard.app")])
    if "CDHash=" + pin + "\n" not in signature.stderr:
        raise RuntimeError("client pin mismatch")
    before = hashlib.sha256(Path("/etc/pf.conf").read_bytes()).hexdigest()
    created = []
    right_created = False
    try:
        BASE.mkdir(mode=0o755); created.append(BASE)
        (BASE / "state").mkdir(mode=0o700)
        intent = BASE / "state/intent.json"
        intent.write_text(json.dumps({"version": 1, "enabled": False}))
        intent.chmod(0o600)
        copy(KIT / "client-pin", BASE / "client-pin", 0o600)
        copy(KIT / "RegisterManagementRight", BASE / "RegisterManagementRight", 0o700)
        created.append(HELPER); copy(KIT / "org.v2boxkillswitch.helper", HELPER, 0o755)
        created.append(BACKEND); copy(KIT / "org.v2boxkillswitch.backend", BACKEND, 0o755)
        created.append(DAEMON); copy(KIT / "org.v2boxkillswitch.helper.plist", DAEMON, 0o644)
        created.append(APP); shutil.copytree(KIT / "V2BoxGuard.app", APP)
        # root owns newly copied files; disallow other-user/group writes throughout.
        for entry in [APP, *APP.rglob("*")]:
            os.chown(entry, 0, 0)
            entry.chmod(entry.stat().st_mode & ~0o022)
        command([str(BASE / "RegisterManagementRight"), "--register-management-right"])
        right_created = True
        # There is deliberately no approved.json and no PF gate/config changes.
        command(["/bin/launchctl", "bootstrap", "system", str(DAEMON)])
        if hashlib.sha256(Path("/etc/pf.conf").read_bytes()).hexdigest() != before:
            raise RuntimeError("PF configuration changed during install; stop and review")
        print("Installed helper OFF for IPC testing. No approved policy or PF changes.")
    except Exception:
        subprocess.run(["/bin/launchctl", "bootout", "system/org.v2boxkillswitch.helper"], capture_output=True)
        if right_created:
            subprocess.run(["/usr/bin/security", "authorizationdb", "remove", "org.v2boxkillswitch.manage"], capture_output=True)
        for entry in reversed(created):
            if entry.is_dir(): shutil.rmtree(entry)
            else: entry.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("OFF-state installation failed:", error, file=sys.stderr)
        raise SystemExit(1)
