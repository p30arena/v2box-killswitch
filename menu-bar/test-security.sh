#!/bin/bash
# Pure requirement parsing/input validation; no IPC or authorization prompts.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SDK="${SDKROOT:-$(/usr/bin/xcrun --sdk macosx --show-sdk-path)}"
mkdir -p "$ROOT/.build/security-tests"
/usr/bin/swiftc -sdk "$SDK" -module-cache-path "$ROOT/.build/manual/ModuleCache" \
  -framework Foundation -framework Security "$ROOT/Security/PeerSecurity.swift" \
  "$ROOT/SecurityTests/main.swift" -o "$ROOT/.build/security-tests/BoundaryTests"
"$ROOT/.build/security-tests/BoundaryTests"
