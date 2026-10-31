# Menu-bar UI preview — not operational protection

This native AppKit preview has simulated enable/disable controls only. It does
not inspect or change PF, launchd, VPN state, or system settings. It always labels
itself DEMO and actual protection as NOT INSPECTED. It cannot recover connectivity.

## Build without installing or running

```sh
bash menu-bar/build-preview.sh
```

The script invokes `swiftc` directly, avoiding Swift Package Manager's platform
lookup failure on some Command Line Tools installations. It normally gets the SDK
path from `xcrun --sdk macosx --show-sdk-path`. If necessary specify an existing SDK:

```sh
SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX13.3.sdk bash menu-bar/build-preview.sh
```

Output: `menu-bar/.build/manual/V2BoxGuardPreview`. Building does not launch it.
No developer-tool selection changes or dependency installs are required.

To package an uninstalled, unsigned demo app bundle (also does not launch it):

```sh
bash menu-bar/package-preview.sh
```

Output: `menu-bar/.build/V2BoxGuardPreview.app`. This is visibly DEMO and still
has simulated controls only.

The privileged controller described in `../docs/MENU-BAR.md` remains unimplemented.
