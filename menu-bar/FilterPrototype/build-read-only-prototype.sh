#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."

sdk="$(xcrun --show-sdk-path --sdk macosx)"
identity="${SIGNING_IDENTITY:--}"
adhoc_entitlements="${ADHOC_ENTITLEMENTS:-0}"
team_id="${TEAM_ID:-TEAMID}"
target_device_id="${TARGET_DEVICE_UDID:-}"
app_profile="${APP_PROFILE:-}"
extension_profile="${EXTENSION_PROFILE:-}"
packet_extension_profile="${PACKET_EXTENSION_PROFILE:-}"

if [[ "$identity" != "-" ]]; then
  [[ "$identity" == "Apple Development:"* ]] || {
    echo "This local prototype requires an Apple Development identity, not Developer ID distribution signing." >&2
    exit 2
  }
  [[ "$team_id" != "TEAMID" && -n "$target_device_id" && -f "$app_profile" && -f "$extension_profile" && -f "$packet_extension_profile" ]] || {
    echo "For Apple Development signing set TEAM_ID, TARGET_DEVICE_UDID, APP_PROFILE, EXTENSION_PROFILE, and PACKET_EXTENSION_PROFILE." >&2
    exit 2
  }
  python3 menu-bar/FilterPrototype/validate-profiles.py \
    "$team_id" "$target_device_id" "$app_profile" "$extension_profile" "$packet_extension_profile"
elif [[ "$adhoc_entitlements" != "0" && "$adhoc_entitlements" != "1" ]]; then
  echo "ADHOC_ENTITLEMENTS must be 0 or 1." >&2
  exit 2
fi

if [[ "$identity" == "-" ]]; then
  if [[ "$adhoc_entitlements" == "1" ]]; then
    build_dir="$PWD/.build/filter-prototype-self-signed"
  else
    build_dir="$PWD/.build/filter-prototype-adhoc"
  fi
else
  build_dir="$PWD/.build/filter-prototype-$team_id"
fi
app="$build_dir/V2BoxFirewallObserver.app"
extension="$app/Contents/Library/SystemExtensions/org.v2boxkillswitch.firewallprobe.extension.systemextension"
packet_extension="$app/Contents/Library/SystemExtensions/org.v2boxkillswitch.firewallprobe.packet.systemextension"
slice_dir="$build_dir/.slices"
mkdir -p "$app/Contents/MacOS" "$extension/Contents/MacOS" "$packet_extension/Contents/MacOS"
mkdir -p "$slice_dir"

for arch in x86_64 arm64; do
  target="$arch-apple-macosx13.0"
  xcrun swiftc -sdk "$sdk" -target "$target" \
    menu-bar/FilterPrototype/FlowProbe.swift -o "$slice_dir/FlowProbe-$arch"
  xcrun swiftc -parse-as-library -sdk "$sdk" -target "$target" \
    -module-name V2BoxReadOnlyFlowObserver -framework NetworkExtension \
    menu-bar/FilterPrototype/ReadOnlyFlowObserver.swift \
    menu-bar/FilterPrototype/ExtensionMain.swift \
    -o "$slice_dir/V2BoxReadOnlyFlowObserver-$arch"
  xcrun swiftc -parse-as-library -sdk "$sdk" -target "$target" \
    -module-name V2BoxReadOnlyPacketObserver -framework NetworkExtension -framework Network \
    menu-bar/FilterPrototype/ReadOnlyPacketObserver.swift \
    menu-bar/FilterPrototype/ExtensionMain.swift \
    -o "$slice_dir/V2BoxReadOnlyPacketObserver-$arch"

  xcrun swiftc -parse-as-library -sdk "$sdk" -target "$target" \
    -module-name V2BoxFirewallObserver -framework AppKit \
    -framework NetworkExtension -framework SystemExtensions \
    menu-bar/FilterPrototype/ObserverHost.swift \
    -o "$slice_dir/V2BoxFirewallObserver-$arch"
done

xcrun lipo -create \
  "$slice_dir/V2BoxReadOnlyFlowObserver-x86_64" \
  "$slice_dir/V2BoxReadOnlyFlowObserver-arm64" \
  -output "$extension/Contents/MacOS/V2BoxReadOnlyFlowObserver"
xcrun lipo -create \
  "$slice_dir/V2BoxReadOnlyPacketObserver-x86_64" \
  "$slice_dir/V2BoxReadOnlyPacketObserver-arm64" \
  -output "$packet_extension/Contents/MacOS/V2BoxReadOnlyPacketObserver"
xcrun lipo -create \
  "$slice_dir/V2BoxFirewallObserver-x86_64" \
  "$slice_dir/V2BoxFirewallObserver-arm64" \
  -output "$app/Contents/MacOS/V2BoxFirewallObserver"

xcrun lipo -create "$slice_dir/FlowProbe-x86_64" "$slice_dir/FlowProbe-arm64" \
  -output "$build_dir/FlowProbe"
codesign --force --sign - --identifier org.v2boxkillswitch.firewallprobe.testprobe "$build_dir/FlowProbe"
codesign --verify --strict "$build_dir/FlowProbe"

cp menu-bar/FilterPrototype/Host-Info.plist "$app/Contents/Info.plist"
cp menu-bar/FilterPrototype/Extension-Info.plist "$extension/Contents/Info.plist"
cp menu-bar/FilterPrototype/PacketExtension-Info.plist "$packet_extension/Contents/Info.plist"

if [[ "$identity" != "-" ]]; then
  cp "$app_profile" "$app/Contents/embedded.provisionprofile"
  cp "$extension_profile" "$extension/Contents/embedded.provisionprofile"
  cp "$packet_extension_profile" "$packet_extension/Contents/embedded.provisionprofile"
  codesign --force --sign "$identity" \
    --entitlements menu-bar/FilterPrototype/Extension.entitlements \
    "$extension"
  codesign --force --sign "$identity" \
    --entitlements menu-bar/FilterPrototype/PacketExtension.entitlements \
    "$packet_extension"
  codesign --force --sign "$identity" \
    --entitlements menu-bar/FilterPrototype/Host.entitlements "$app"
else
  if [[ "$adhoc_entitlements" == "1" ]]; then
    # Deliberately unprovisioned experiment requested for this local Mac only.
    # The OS may reject these claims; this must never be treated as an authorized
    # or distributable build.
    codesign --force --sign - --entitlements \
      menu-bar/FilterPrototype/Extension.entitlements "$extension"
    codesign --force --sign - --entitlements \
      menu-bar/FilterPrototype/PacketExtension.entitlements "$packet_extension"
    codesign --force --sign - --entitlements \
      menu-bar/FilterPrototype/Host.entitlements "$app"
  else
    # Package-only local build. No restricted entitlements are claimed, so this
    # ad-hoc app cannot activate the filter. Never run it as a firewall.
    codesign --force --sign - "$extension"
    codesign --force --sign - "$packet_extension"
    codesign --force --sign - "$app"
  fi
fi

codesign --verify --strict --verbose=2 "$app"
codesign --verify --strict --verbose=2 "$extension"
codesign --verify --strict --verbose=2 "$packet_extension"
echo "Built $app"
