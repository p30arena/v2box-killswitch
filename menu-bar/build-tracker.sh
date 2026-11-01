#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
APP="$PWD/.build/V2Box Reconnect Tracker.app"
mkdir -p "$APP/Contents/MacOS"
/usr/bin/plutil -create xml1 "$APP/Contents/Info.plist" 2>/dev/null || true
/usr/bin/python3 -I - "$APP/Contents/Info.plist" <<'PY'
import plistlib,sys
with open(sys.argv[1], 'wb') as f:
    plistlib.dump({'CFBundleIdentifier':'org.v2boxkillswitch.reconnecttracker',
                  'CFBundleName':'V2Box Reconnect Tracker','CFBundleDisplayName':'V2Box Reconnect Tracker',
                  'CFBundleExecutable':'V2BoxReconnectTracker','CFBundlePackageType':'APPL',
                  'CFBundleShortVersionString':'0.1.0','CFBundleVersion':'1',
                  'LSMinimumSystemVersion':'13.0','LSUIElement':True}, f)
PY
xcrun swiftc -O -target "$(uname -m)-apple-macosx13.0" \
  menu-bar/Sources/V2BoxReconnectTracker/TrackerCore.swift \
  menu-bar/Sources/V2BoxReconnectTracker/NativeTracker.swift \
  menu-bar/Sources/V2BoxReconnectTracker/main.swift \
  -framework AppKit -framework SystemConfiguration -framework UserNotifications \
  -o "$APP/Contents/MacOS/V2BoxReconnectTracker"
codesign --force --sign - --options runtime --timestamp=none "$APP"
codesign --verify --strict "$APP"
printf 'Built only; not launched or installed: %s\n' "$APP"
