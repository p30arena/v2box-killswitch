#!/usr/bin/env python3
"""BUILD ONLY: unprivileged bundled XPC diagnostic. Does not launch/register it.

Actual --run-read-only execution requires a separate approved diagnostic plan.
No root helper, policy, timer, launch plist, startup item or installed state write.
"""
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
MENU = ROOT / "menu-bar"
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}


def command(args):
    subprocess.run([str(arg) for arg in args], env=ENV, check=True, timeout=120)


def cdhash(path):
    result = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)],
                            env=ENV, capture_output=True, text=True, check=True, timeout=10)
    match = re.search(r"^CDHash=([a-f0-9]{40})$", result.stdout + result.stderr, re.M)
    if not match: raise RuntimeError("missing diagnostic signature")
    return match.group(1)


def write_plist(path, value):
    path.write_bytes(plistlib.dumps(value, sort_keys=True))


def main():
    if os.geteuid() == 0 or sys.argv[1:] != ["--build-only"]:
        raise RuntimeError("unprivileged explicit build-only flag required")
    suffix = uuid.uuid4().hex[:16]
    directory = ROOT / ".build" / ("read-only-xpc-" + suffix)
    directory.mkdir(parents=True, mode=0o700)
    directory.chmod(0o700)
    app = directory / "RecoveryBridgeFixture.app"
    parent_id = "org.v2boxkillswitch.fixture." + suffix
    service_id = parent_id + ".service"
    service = app / "Contents" / "XPCServices" / "ReadOnlyBridge.xpc"
    config = directory / "fixture-config.json"
    for bundle in (app, service):
        (bundle / "Contents" / "MacOS").mkdir(parents=True)
    parent_bin = app / "Contents" / "MacOS" / "RecoveryBridgeFixture"
    service_bin = service / "Contents" / "MacOS" / "ReadOnlyBridge"
    common = {"CFBundleVersion": "1", "CFBundleShortVersionString": "0.0.1",
              "LSMinimumSystemVersion": "13.0", "FixtureConfigPath": str(config)}
    write_plist(app / "Contents" / "Info.plist", dict(common,
        CFBundleIdentifier=parent_id, CFBundleExecutable=parent_bin.name,
        CFBundleName="Read-only Recovery Bridge Fixture", CFBundlePackageType="APPL", LSUIElement=True))
    write_plist(service / "Contents" / "Info.plist", dict(common,
        CFBundleIdentifier=service_id, CFBundleExecutable=service_bin.name, CFBundlePackageType="XPC!",
        XPCService={"ServiceType": "Application", "RunLoopType": "NSRunLoop", "JoinExistingSession": True}))
    sdk = subprocess.check_output(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"],
                                  env=ENV, text=True, timeout=10).strip()
    compile_common = ["/usr/bin/swiftc", "-sdk", sdk, "-module-cache-path", MENU / ".build/manual/ModuleCache",
        "-framework", "Foundation", "-framework", "Security", "-lproc", "-import-objc-header",
        MENU / "Sources/V2BoxGuardRecoveryWorker/ProcessInfo.h", MENU / "Security/PeerSecurity.swift",
        MENU / "Security/RecoveryPeer.swift", MENU / "Security/RecoveryHandoff.swift",
        MENU / "CrossProcessFixture/FixtureConfig.swift"]
    command(compile_common + [MENU / "CrossProcessFixture/Service/main.swift", "-o", service_bin])
    command(compile_common + [MENU / "CrossProcessFixture/Parent/main.swift", "-o", parent_bin])
    for bundle in (service, app):  # Nested code first; NEVER deep-resign a child afterward.
        command(["/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime", "--timestamp=none", bundle])
    command(["/usr/bin/codesign", "--verify", "--strict", service])
    command(["/usr/bin/codesign", "--verify", "--strict", app])
    # External user-owned TEST config avoids circular mutual-CDHash signing.
    value = {"uid": os.geteuid(), "ticket": uuid.uuid4().hex, "service_name": service_id,
             "parent_hash": cdhash(app), "service_hash": cdhash(service), "parent_pid": 0,
             "parent_birth_seconds": 0, "parent_birth_microseconds": 0}
    config.write_text(json.dumps(value, separators=(",", ":")) + "\n")
    config.chmod(0o600)
    metadata = {"built_only": True, "launched": False, "root_operations": False,
                "app": str(app), "result": str(directory / "result.json"), "service_watchdog_seconds": 15,
                "proposed_command": [str(parent_bin), "--run-read-only"]}
    (directory / "build-only.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print("Built/signature-checked ONLY. No app/service launched or registered by this tool.")
    print("Pending separate approval; NOT RUN:", shlex.join(metadata["proposed_command"]))
    print("Build record:", directory / "build-only.json")


if __name__ == "__main__": main()
