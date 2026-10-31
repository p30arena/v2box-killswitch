#!/bin/bash
# Read-only prototype only. No VPN executor, installation or registration.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SDK="${SDKROOT:-$(/usr/bin/xcrun --sdk macosx --show-sdk-path)}"
mkdir -p "$ROOT/.build/recovery-worker"
/usr/bin/swiftc -sdk "$SDK" -module-cache-path "$ROOT/.build/manual/ModuleCache" \
  -framework Foundation -framework SystemConfiguration -lproc \
  -import-objc-header "$ROOT/Sources/V2BoxGuardRecoveryWorker/ProcessInfo.h" \
  "$ROOT/Sources/V2BoxGuardRecoveryWorker/ReadOnlyChildSupervisor.swift" \
  "$ROOT/Sources/V2BoxGuardRecoveryWorker/main.swift" \
  -o "$ROOT/.build/recovery-worker/V2BoxGuardRecoveryWorker"
/usr/bin/codesign --force --sign - --options runtime --timestamp=none \
  "$ROOT/.build/recovery-worker/V2BoxGuardRecoveryWorker"
echo 'Built hardened, ad-hoc signed read-only recovery worker. No VPN executor. NOT installed or registered.'
