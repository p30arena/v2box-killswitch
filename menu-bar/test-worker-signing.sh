#!/bin/bash
# Local artifact copies + anonymous IN-PROCESS XPC. No service or installation.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd -P)"
SDK="${SDKROOT:-$(/usr/bin/xcrun --sdk macosx --show-sdk-path)}"
bash "$ROOT/build-recovery-worker.sh"
OUT="$ROOT/.build/worker-signing-tests/WorkerSigningTests"
mkdir -p "$(dirname "$OUT")"
FIXTURES=$(/usr/bin/mktemp -d "$ROOT/.build/worker-signing-fixtures.XXXXXX")
trap 'rm -rf "$FIXTURES"' EXIT
WORKER="$ROOT/.build/recovery-worker/V2BoxGuardRecoveryWorker"
cp "$WORKER" "$FIXTURES/plain"
cp "$WORKER" "$FIXTURES/entitled"
/usr/bin/codesign --force --sign - --options 0 --timestamp=none "$FIXTURES/plain"
/usr/bin/codesign --force --sign - --options runtime --timestamp=none \
  --entitlements "$ROOT/WorkerSigningTests/unsafe-entitlements.plist" "$FIXTURES/entitled"
/usr/bin/swiftc -sdk "$SDK" -module-cache-path "$ROOT/.build/manual/ModuleCache" -typecheck \
  -framework Foundation -framework Security "$ROOT/Security/PeerSecurity.swift" \
  "$ROOT/Security/WorkerArtifact.swift" "$ROOT/Security/RecoveryPeer.swift"
/usr/bin/swiftc -sdk "$SDK" -module-cache-path "$ROOT/.build/manual/ModuleCache" -D WORKER_ARTIFACT_FIXTURES \
  -framework Foundation -framework Security "$ROOT/Security/PeerSecurity.swift" \
  "$ROOT/Security/WorkerArtifact.swift" "$ROOT/Security/RecoveryPeer.swift" \
  "$ROOT/WorkerSigningTests/main.swift" -o "$OUT"
/usr/bin/codesign --force --sign - --options runtime --timestamp=none "$OUT"
hash() {
  /usr/bin/codesign -d --verbose=4 "$1" 2>&1 | /usr/bin/awk -F= '/^CDHash=/{print $2}'
}
"$OUT" "$WORKER" "$(hash "$WORKER")" "$(hash "$OUT")" \
  "$FIXTURES/plain" "$(hash "$FIXTURES/plain")" \
  "$FIXTURES/entitled" "$(hash "$FIXTURES/entitled")" "$FIXTURES"
