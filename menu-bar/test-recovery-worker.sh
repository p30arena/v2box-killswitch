#!/bin/bash
# Unprivileged, read-only identity and pipe-handshake checks. No VPN execution.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
bash "$ROOT/build-recovery-worker.sh"
/usr/bin/python3 -I "$ROOT/RecoveryWorkerTests/test_worker.py" \
  "$ROOT/.build/recovery-worker/V2BoxGuardRecoveryWorker"
