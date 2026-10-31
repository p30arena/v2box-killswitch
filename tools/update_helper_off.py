#!/usr/bin/env python3
"""Update only a previously installed OFF-state test helper. No PF mutations."""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

BASE = Path("/Library/Application Support/V2BoxGuard")
KIT = Path(__file__).resolve().parents[1] / ".build/development-kit"
TARGETS = {
    "org.v2boxkillswitch.helper": (Path("/Library/PrivilegedHelperTools/org.v2boxkillswitch.helper"), 0o755),
    "org.v2boxkillswitch.backend": (Path("/Library/PrivilegedHelperTools/org.v2boxkillswitch.backend"), 0o755),
    "org.v2boxkillswitch.helper.plist": (Path("/Library/LaunchDaemons/org.v2boxkillswitch.helper.plist"), 0o644),
    "client-pin": (BASE / "client-pin", 0o600),
    "V2BoxGuard.app": (BASE / "V2BoxGuard.app", 0o755),
    "RegisterManagementRight": (BASE / "RegisterManagementRight", 0o700),
}


def run(args):
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=30)


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ["--update-off"]:
        raise RuntimeError("root and explicit --update-off required")
    for directory in (BASE, BASE / "state", Path("/Library/PrivilegedHelperTools"), Path("/Library/LaunchDaemons")):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("untrusted installed directory")
    if (BASE / "approved.json").exists(): raise RuntimeError("configured deployment refused")
    if json.loads((BASE / "state/intent.json").read_text()) != {"version": 1, "enabled": False}:
        raise RuntimeError("protection intent is not off")
    if run(["/sbin/pfctl", "-a", "com.p30arena.v2box-killswitch", "-sr"]).stdout.strip():
        raise RuntimeError("project rules are loaded; update refused")
    stage = Path(tempfile.mkdtemp(prefix=".off-update-", dir=BASE))
    new = stage / "new"; old = stage / "old"
    new.mkdir(); old.mkdir()
    moved = []
    stopped = False
    try:
        for name, (target, mode) in TARGETS.items():
            info = target.lstat()
            if info.st_uid != 0 or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022:
                raise RuntimeError("unsafe installed target")
            source = KIT / name
            if any(x.is_symlink() for x in [source, *source.rglob("*")]):
                raise RuntimeError("symlink in new artifact refused")
            if source.is_dir(): shutil.copytree(source, new / name)
            else: shutil.copyfile(source, new / name)
            (new / name).chmod(mode)
            if source.is_dir():
                for entry in (new / name).rglob("*"):
                    entry.chmod(entry.stat().st_mode & ~0o022)
        for name in ("V2BoxGuard.app", "org.v2boxkillswitch.helper"):
            run(["/usr/bin/codesign", "--verify", "--strict", str(new / name)])
        signature = run(["/usr/bin/codesign", "-d", "--verbose=4", str(new / "V2BoxGuard.app")])
        if "CDHash=" + (new / "client-pin").read_text().strip() + "\n" not in signature.stderr:
            raise RuntimeError("new client pin mismatch")
        run(["/bin/launchctl", "bootout", "system/org.v2boxkillswitch.helper"])
        stopped = True
        for name, (target, _) in TARGETS.items():
            os.replace(target, old / name)
            moved.append(name)
            os.replace(new / name, target)
        run(["/bin/launchctl", "bootstrap", "system", str(TARGETS["org.v2boxkillswitch.helper.plist"][0])])
        status = json.loads(run([str(TARGETS["org.v2boxkillswitch.backend"][0]), "status"]).stdout)
        if status.get("state") != "off": raise RuntimeError("updated backend did not report off")
        print("Updated OFF-state helper. Backup retained at", old)
        print("No PF enable, disable, load or flush operation performed.")
    except Exception:
        if stopped:
            subprocess.run(["/bin/launchctl", "bootout", "system/org.v2boxkillswitch.helper"], capture_output=True)
            for name in reversed(moved):
                target = TARGETS[name][0]
                if target.exists():
                    if target.is_dir(): shutil.rmtree(target)
                    else: target.unlink()
                os.replace(old / name, target)
            subprocess.run(["/bin/launchctl", "bootstrap", "system", str(TARGETS["org.v2boxkillswitch.helper.plist"][0])], capture_output=True)
        raise


if __name__ == "__main__":
    try: main()
    except Exception as error:
        print("OFF-state update stopped:", error, file=sys.stderr)
        raise SystemExit(1)
