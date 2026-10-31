#!/usr/bin/env python3
"""Build/sign only local development artifacts. NO installation or registration."""
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / ".build" / "development-kit"


def command(args):
    return subprocess.run(args, cwd=ROOT, check=True, capture_output=True, text=True)


def cdhash(path):
    result = command(["/usr/bin/codesign", "-d", "--verbose=4", str(path)])
    match = re.search(r"(?m)^CDHash=([0-9a-f]{40})$", result.stderr)
    if not match:
        raise RuntimeError("cannot extract signed artifact CDHash")
    return match.group(1)


def main():
    command([sys.executable, "tools/build_backend.py"])
    command(["bash", "menu-bar/build-helper.sh"])
    command(["bash", "menu-bar/package-client.sh"])
    KIT.mkdir(parents=True, exist_ok=True)
    helper = KIT / "org.v2boxkillswitch.helper"
    shutil.copyfile(ROOT / "menu-bar/.build/helper/V2BoxGuardHelper", helper)
    helper.chmod(0o755)
    command(["/usr/bin/codesign", "--force", "--sign", "-", str(helper)])
    helper_hash = cdhash(helper)
    app = KIT / "V2BoxGuard.app"
    if app.exists():
        shutil.rmtree(app)  # only this generated app within ignored .build
    shutil.copytree(ROOT / "menu-bar/.build/V2BoxGuardClient.app", app)
    info = app / "Contents/Info.plist"
    with info.open("rb") as source:
        data = plistlib.load(source)
    data["GuardHelperCDHash"] = helper_hash
    with info.open("wb") as target:
        plistlib.dump(data, target)
    command(["/usr/bin/codesign", "--force", "--sign", "-", str(app)])
    (KIT / "client-pin").write_text(cdhash(app) + "\n")
    shutil.copyfile(ROOT / ".build/org.v2boxkillswitch.backend", KIT / "org.v2boxkillswitch.backend")
    (KIT / "org.v2boxkillswitch.backend").chmod(0o755)
    shutil.copyfile(ROOT / "config/org.v2boxkillswitch.helper.plist", KIT / "org.v2boxkillswitch.helper.plist")
    sdk = command(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"]).stdout.strip()
    command(["/usr/bin/swiftc", "-sdk", sdk, "-module-cache-path", str(ROOT / "menu-bar/.build/manual/ModuleCache"),
             "-framework", "Security", "menu-bar/Provisioning/main.swift", "-o", str(KIT / "RegisterManagementRight")])
    for artifact in (helper, app):
        command(["/usr/bin/codesign", "--verify", "--strict", str(artifact)])
    print("Built and ad-hoc signed development kit:", KIT)
    print("NOT installed, registered, launched or activated. NOT notarized or release-ready.")


if __name__ == "__main__":
    main()
