#!/bin/bash
# Build a demo .app bundle only. Never installs, registers, launches or changes PF.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
APP="$ROOT/.build/V2BoxGuardPreview.app"
SDK="${SDKROOT:-$(/usr/bin/xcrun --sdk macosx --show-sdk-path)}"
[[ -d "$SDK/System/Library/Frameworks/AppKit.framework" ]] || { echo "Invalid macOS SDK: $SDK" >&2; exit 1; }
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
/usr/bin/swiftc -sdk "$SDK" -module-cache-path "$ROOT/.build/manual/ModuleCache" \
  -framework AppKit "$ROOT/Sources/V2BoxGuardPreview/main.swift" \
  -o "$APP/Contents/MacOS/V2BoxGuardPreview"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>V2BoxGuardPreview</string>
<key>CFBundleIdentifier</key><string>org.v2boxkillswitch.preview.demo</string>
<key>CFBundleName</key><string>V2Box Guard PREVIEW ONLY</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSUIElement</key><true/>
<key>NSHighResolutionCapable</key><true/>
<key>CFBundleVersion</key><string>0.0.1</string>
<key>CFBundleShortVersionString</key><string>0.0.1-DEMO</string>
</dict></plist>
PLIST
/usr/bin/plutil -lint "$APP/Contents/Info.plist"
echo "Built demo only: $APP"
echo "It is not signed, installed, registered, launched, or connected to system controls."
