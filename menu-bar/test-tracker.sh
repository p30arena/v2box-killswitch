#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .build
xcrun swiftc menu-bar/Sources/V2BoxReconnectTracker/TrackerCore.swift \
  menu-bar/TrackerTests/main.swift -o .build/tracker-tests
.build/tracker-tests
bash menu-bar/build-tracker.sh
# Deliberately do not launch the tracker, install a job, or exercise real Start.
# Optional read-only subscription diagnostic (Start is hard-disabled):
if [[ "${1:-}" == "--read-only-native" ]]; then
  xcrun swiftc menu-bar/Sources/V2BoxReconnectTracker/{TrackerCore.swift,NativeTracker.swift} \
    menu-bar/TrackerTests/ReadOnly/main.swift -framework SystemConfiguration -o .build/tracker-read-only
  .build/tracker-read-only
fi
