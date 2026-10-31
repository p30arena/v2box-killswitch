#!/usr/bin/env python3
"""Explicit root-only READ-ONLY console credential/bootstrap launch validation.

Only fixed Apple id/launchctl identity queries. No worker install, scutil, PF
writes, service registration, user-selected UID or arbitrary command argument.
"""
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ["--check-only"]:
        raise RuntimeError("root and explicit read-only flag required")
    sys.path.insert(0, str(ROOT / "tools"))
    from verify_diagnostics_off import verify_off
    verify_off()  # Basic Off checks only; no source/artifact comparison or write.
    sys.path.insert(0, str(ROOT / "src"))
    from session_launch import check_user_launch, user_uid
    uid = os.stat("/dev/console").st_uid
    user_uid(uid)
    account = pwd.getpwuid(uid)
    groups = set(os.getgrouplist(account.pw_name, account.pw_gid))
    result = check_user_launch(uid, account.pw_gid, groups,
        lambda args, **kwargs: subprocess.run(args, capture_output=True, text=True, check=False,
                                             stdin=subprocess.DEVNULL, **kwargs))
    if os.stat("/dev/console").st_uid != uid:
        raise RuntimeError("console owner changed during validation")
    verify_off()
    print(json.dumps({"verified": result.verified, "reason": result.reason,
                      "protection": "off", "pf": "disabled", "trial_timer": "unloaded",
                      "vpn_commands_used": False, "installed_or_registered": False}))
    if not result.verified: raise SystemExit(1)


if __name__ == "__main__":
    try: main()
    except Exception as error:
        print("Read-only user-session validation stopped:", type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
