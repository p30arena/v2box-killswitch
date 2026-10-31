#!/bin/bash
# Build only. Does not launch, install, sign, or change system settings.
set -euo pipefail
cd "$(dirname "$0")"
SDK="${SDKROOT:-}"
if [[ -z "$SDK" ]]; then
  SDK=$(/usr/bin/xcrun --sdk macosx --show-sdk-path)
fi
if [[ ! -d "$SDK/System/Library/Frameworks/AppKit.framework" ]]; then
  printf 'Invalid SDK: %s\nSet SDKROOT to an installed macOS SDK directory.\n' "$SDK" >&2
  exit 1
fi
mkdir -p .build/manual
/usr/bin/swiftc -sdk "$SDK" -module-cache-path .build/manual/ModuleCache \
  -framework AppKit Sources/V2BoxGuardPreview/main.swift \
  -o .build/manual/V2BoxGuardPreview
printf 'Built preview only: %s/.build/manual/V2BoxGuardPreview\n' "$PWD"
