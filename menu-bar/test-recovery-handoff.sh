#!/bin/bash
# Anonymous IN-PROCESS endpoint transfer; no Mach-service registration or install.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SDK="${SDKROOT:-$(/usr/bin/xcrun --sdk macosx --show-sdk-path)}"
OUT="$ROOT/.build/recovery-handoff-tests/RecoveryHandoffTests"
mkdir -p "$(dirname "$OUT")"
/usr/bin/swiftc -sdk "$SDK" -module-cache-path "$ROOT/.build/manual/ModuleCache" \
  -framework Foundation -framework Security "$ROOT/Security/PeerSecurity.swift" \
  "$ROOT/Security/RecoveryPeer.swift" "$ROOT/Security/RecoveryHandoff.swift" \
  "$ROOT/RecoveryHandoffTests/main.swift" -o "$OUT"
/usr/bin/codesign --force --sign - --options runtime --timestamp=none "$OUT"
HASH=$(/usr/bin/codesign -d --verbose=4 "$OUT" 2>&1 | /usr/bin/awk -F= '/^CDHash=/{print $2}')
[[ "$HASH" =~ ^[0-9a-f]{40}$ ]] || { echo 'Missing fixture hash' >&2; exit 1; }
"$OUT" "$HASH"
