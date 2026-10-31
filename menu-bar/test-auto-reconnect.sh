#!/bin/bash
# Injected unit tests only. Never invokes the real native VPN adapter.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SDK="${SDKROOT:-$(/usr/bin/xcrun --sdk macosx --show-sdk-path)}"
OUT="$ROOT/.build/auto-reconnect-tests/AutoReconnectTests"
mkdir -p "$(dirname "$OUT")"
/usr/bin/swiftc -sdk "$SDK" -module-cache-path "$ROOT/.build/manual/ModuleCache" \
  -framework Foundation -framework SystemConfiguration \
  "$ROOT/Sources/V2BoxGuardClient/AutoReconnect.swift" \
  "$ROOT/Sources/V2BoxGuardClient/HelperPreflight.swift" \
  "$ROOT/AutoReconnectTests/main.swift" -o "$OUT"
"$OUT"
