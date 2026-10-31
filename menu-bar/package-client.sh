#!/bin/bash
# Package XPC client UI only. There is no helper/service in this repository.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
APP="$ROOT/.build/V2BoxGuardClient.app"
SDK="${SDKROOT:-$(/usr/bin/xcrun --sdk macosx --show-sdk-path)}"
[[ -d "$SDK/System/Library/Frameworks/AppKit.framework" ]] || { echo "Invalid macOS SDK: $SDK" >&2; exit 1; }
mkdir -p "$APP/Contents/MacOS"
/usr/bin/swiftc -sdk "$SDK" -module-cache-path "$ROOT/.build/manual/ModuleCache" \
  -framework AppKit -framework Security "$ROOT/Security/PeerSecurity.swift" \
  "$ROOT/Sources/V2BoxGuardClient/main.swift" \
  -o "$APP/Contents/MacOS/V2BoxGuardClient"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>V2BoxGuardClient</string>
<key>CFBundleIdentifier</key><string>org.v2boxkillswitch.client.development</string>
<key>CFBundleName</key><string>V2Box Guard Client (NO HELPER)</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSUIElement</key><true/>
<key>CFBundleVersion</key><string>0.1.0</string>
<key>CFBundleShortVersionString</key><string>0.1.0-DEV</string>
</dict></plist>
PLIST
/usr/bin/plutil -lint "$APP/Contents/Info.plist"
echo "Built UI client only: $APP"
echo "No XPC helper is present; controls remain disabled. Not installed or launched."
