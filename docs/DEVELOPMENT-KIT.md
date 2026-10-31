# Development kit — not installed, not release-ready

Build (no installation or activation):

```sh
python3 tools/build_development_kit.py
```

Output: `.build/development-kit/` contains the menu-bar app, signed helper, isolated
Python backend, matching client pin, LaunchDaemon plist, and a root-only custom
management-right provisioning tool. No build step runs a generated executable.
All signatures are local ad-hoc signatures, not notarized distribution signatures.
Requires macOS 13+, installed Command Line Tools/Python 3, Swift and codesign.

## Source-level operational path

Menu Enable/Disable -> admin authorization -> pinned XPC helper -> fixed root
backend executable -> serialized controller -> scoped PF driver -> kernel read-back.
The helper's ten-second refresh calls the same backend and respects Disable intent.
These paths are implemented, but positive IPC/authentication and actual firewall
behavior have NOT been tested. Calling them operationally verified would be false.

## Prerequisites for a separately approved installation

Do not execute an installation on the development Mac without explicit approval.
There is intentionally no automatic installer while live validation is pending.

A reviewed installer would need to:

1. Back up PF configuration and state, identify unrelated PF owners, establish a
   local console recovery procedure and review the absence of preexisting states.
   Do not globally flush states to satisfy preflight.
2. Remove the legacy project refresher and legacy startup references. The new
   Disable intent cannot control the old implementation. Never install both.
3. Install the helper/backend under the fixed paths in `XPC-HELPER.md`, root-owned
   and not group/world-writable. Install matching `client-pin` root-owned 0600.
   The app must match that exact pin; rebuilding it requires repinning.
4. Create root-owned `/Library/Application Support/V2BoxGuard` and its `state`
   directory (state mode 0700). Install a reviewed `approved.json`, mode 0600.
   `config/approved.json.example` deliberately has an expired inventory, a dummy
   UUID, and a documentation address, so it CANNOT enable as shipped.
5. Review adding this empty gate as the FIRST filter rule in the existing PF
   filter section, preserving translation/scrub/Apple rules:

   ```pf
   anchor "com.p30arena.v2box-killswitch" quick
   ```

   Do not load legacy static rules. Syntax-check the entire proposed config first.
   Reloading global PF config itself is disruptive and requires separate approval.
6. Review/run `RegisterManagementRight --register-management-right` as root to
   register only the custom authenticate-admin right. It refuses to overwrite an
   existing right; do not weaken an existing rule to bypass a failed check.
7. Install/validate the LaunchDaemon plist with the expected Mach service and
   paths. Registration, first service startup, and app launch are separate approved
   steps. Before first Enable, arm an independent local recovery mechanism.
8. Verify actual pinned handshake, denial without authorization, Enable/Disable
   read-back, direct-traffic captures, endpoint and router changes, helper crash,
   GUI failure and persisted Disable. Then separately verify boot behavior.

## Current exclusions

- Automatic user-session reconnect integration is unfinished.
- Arbitrary endpoint changes still require approved inventory updates; no general
  DNS/HTTPS bootstrap bypass is provided.
- Different-boot tokens are rejected; reboot recovery/protection is not proven.
- If the helper is unavailable the UI cannot promise emergency disable. A reviewed
  independent fallback remains necessary before public release.

The public README withdrawal warning remains correct. The kit is for controlled
validation only, not for other people to install as a working security product.
