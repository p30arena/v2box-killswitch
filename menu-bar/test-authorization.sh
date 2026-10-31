#!/bin/bash
# Explicit authorization diagnostics; no PF, helper IPC or service registration.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:---unauthorized-form-only}"
case "$MODE" in
  --unauthorized-form-only|--interactive-authorization-only) ;;
  *) echo 'Unsupported authorization diagnostic mode' >&2; exit 1 ;;
esac
SDK="${SDKROOT:-$(/usr/bin/xcrun --sdk macosx --show-sdk-path)}"
OUT="$ROOT/.build/authorization-tests/AuthorizationRoundtrip"
mkdir -p "$(dirname "$OUT")"
/usr/bin/swiftc -sdk "$SDK" -module-cache-path "$ROOT/.build/manual/ModuleCache" \
  -framework Foundation -framework Security "$ROOT/Security/PeerSecurity.swift" \
  "$ROOT/AuthorizationTests/main.swift" -o "$OUT"
"$OUT" "$MODE"
