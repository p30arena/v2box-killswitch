#!/bin/bash
# Compile only. Never registers, signs, installs or runs the helper.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SDK="${SDKROOT:-$(/usr/bin/xcrun --sdk macosx --show-sdk-path)}"
mkdir -p "$ROOT/.build/helper"
/usr/bin/swiftc -sdk "$SDK" -module-cache-path "$ROOT/.build/manual/ModuleCache" \
  -framework Foundation -framework Security "$ROOT/Security/GuardProtocol.swift" \
  "$ROOT/Security/PeerSecurity.swift" "$ROOT/Sources/V2BoxGuardHelper/main.swift" \
  -o "$ROOT/.build/helper/V2BoxGuardHelper"
echo "Compiled development helper only. NOT installed, registered or launched."
