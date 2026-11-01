#!/usr/bin/env python3
"""Check local Mac development profiles before signing the read-only observer."""

import plistlib
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

APP_ID = "org.v2boxkillswitch.firewallprobe"
EXTENSION_ID = APP_ID + ".extension"
PACKET_EXTENSION_ID = APP_ID + ".packet"
NETWORK_ENTITLEMENT = "com.apple.developer.networking.networkextension"
SYSTEM_EXTENSION_ENTITLEMENT = "com.apple.developer.system-extension.install"
FILTER_CAPABILITY = "content-filter-provider"
APP_GROUP = "group.org.v2boxkillswitch.firewallprobe"
PACKET_APP_GROUP = APP_GROUP + ".packet"


def decode(path: str) -> dict:
    result = subprocess.run(
        ["/usr/bin/security", "cms", "-D", "-i", path],
        check=True,
        capture_output=True,
    )
    value = plistlib.loads(result.stdout)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: decoded profile is not a plist dictionary")
    return value


def check(path: str, team_id: str, bundle_id: str, host: bool,
          target_device_id: str) -> list[str]:
    profile = decode(path)
    errors = []
    team_ids = profile.get("TeamIdentifier", [])
    prefixes = profile.get("ApplicationIdentifierPrefix", [])
    entitlements = profile.get("Entitlements", {})

    if team_id not in team_ids:
        errors.append(f"{path}: TeamIdentifier does not include {team_id}")
    app_identifier = entitlements.get("application-identifier", "")
    if not any(app_identifier == f"{prefix}.{bundle_id}" for prefix in prefixes):
        errors.append(f"{path}: application-identifier does not match {bundle_id}")
    if entitlements.get("com.apple.developer.team-identifier") != team_id:
        errors.append(f"{path}: team-identifier entitlement does not match {team_id}")
    if entitlements.get("get-task-allow") is not True:
        errors.append(f"{path}: profile is not development-enabled (get-task-allow is not true)")
    provisioned_devices = {str(device).upper() for device in profile.get("ProvisionedDevices", [])}
    if target_device_id.upper() not in provisioned_devices:
        errors.append(f"{path}: target Mac {target_device_id} is not in ProvisionedDevices")
    platforms = profile.get("Platform", [])
    if not any(str(platform).lower() in {"osx", "macos"} for platform in platforms):
        errors.append(f"{path}: profile is not a macOS development profile")
    expires = profile.get("ExpirationDate")
    if not isinstance(expires, datetime):
        errors.append(f"{path}: profile is expired or has no valid expiration date")
    else:
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= datetime.now(timezone.utc):
            errors.append(f"{path}: profile is expired or has no valid expiration date")

    network = entitlements.get(NETWORK_ENTITLEMENT, [])
    if FILTER_CAPABILITY not in network:
        errors.append(f"{path}: missing {NETWORK_ENTITLEMENT}={FILTER_CAPABILITY}")
    if host and entitlements.get(SYSTEM_EXTENSION_ENTITLEMENT) is not True:
        errors.append(f"{path}: host profile lacks {SYSTEM_EXTENSION_ENTITLEMENT}=true")
    groups = entitlements.get("com.apple.security.application-groups", [])
    required_groups = [APP_GROUP, PACKET_APP_GROUP] if host else (
        [PACKET_APP_GROUP] if bundle_id == PACKET_EXTENSION_ID else [APP_GROUP]
    )
    for group in required_groups:
        if group not in groups:
            errors.append(f"{path}: profile lacks application group {group}")
    return errors


def main() -> int:
    if len(sys.argv) != 6:
        print("Usage: validate-profiles.py TEAM_ID TARGET_DEVICE_UDID APP_PROFILE EXTENSION_PROFILE PACKET_EXTENSION_PROFILE", file=sys.stderr)
        return 2
    team_id, target_device_id, app_profile, extension_profile, packet_profile = sys.argv[1:]
    for item in (app_profile, extension_profile, packet_profile):
        if not Path(item).is_file():
            print(f"Missing provisioning profile: {item}", file=sys.stderr)
            return 2
    try:
        errors = check(app_profile, team_id, APP_ID, host=True, target_device_id=target_device_id)
        errors += check(extension_profile, team_id, EXTENSION_ID, host=False, target_device_id=target_device_id)
        errors += check(packet_profile, team_id, PACKET_EXTENSION_ID, host=False, target_device_id=target_device_id)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"Could not decode provisioning profile: {error}", file=sys.stderr)
        return 2
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("All three development profiles match the target Mac, bundle IDs, team, and required entitlements.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
