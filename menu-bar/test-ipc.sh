#!/bin/bash
# Compile/sign/run an unprivileged anonymous IPC test. No registered service or PF.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SDK="${SDKROOT:-$(/usr/bin/xcrun --sdk macosx --show-sdk-path)}"
OUT="$ROOT/.build/ipc-tests/IdentityTests"
mkdir -p "$(dirname "$OUT")"
/usr/bin/swiftc -sdk "$SDK" -module-cache-path "$ROOT/.build/manual/ModuleCache" \
  -framework Foundation -framework Security "$ROOT/Security/PeerSecurity.swift" \
  "$ROOT/IPCTests/main.swift" -o "$OUT"
/usr/bin/codesign --force --sign - "$OUT"
HASH=$(/usr/bin/codesign -d --verbose=4 "$OUT" 2>&1 | /usr/bin/awk -F= '/^CDHash=/{print $2}')
[[ "$HASH" =~ ^[0-9a-f]{40}$ ]] || { echo 'Missing test binary CDHash' >&2; exit 1; }
"$OUT" "$HASH"
