# Native client/helper boundary — development implementation

Shared protocol: `menu-bar/Security/GuardProtocol.swift`.
Client: `menu-bar/Sources/V2BoxGuardClient/main.swift`.
Helper: `menu-bar/Sources/V2BoxGuardHelper/main.swift`.
Backend: isolated zipapp built from `src/runtime.py` and its local modules.

Building does not install or run components. The explicit Off-state installer can
register the helper for IPC tests, separately from firewall activation. Standalone
client packaging supplies no helper pin; the full development-kit builder
signs/pins both artifacts locally.

## Authentication and authorization

macOS 13+ `NSXPCConnection.setCodeSigningRequirement` pins an exact approved
40-hex CDHash before resuming connections. The client pins the helper and the
helper pins the client. Foundation validates messages; no PID-based lookup or
claimed bundle-ID check substitutes for identity. Anonymous same-process positive
and negative handshake tests pass; cross-process installed-helper validation is
still pending. Updates require explicit repinning. Before sending an authorization
form, the client requires a signed status response on the SAME connection.

UI protection changes obtain `org.v2boxkillswitch.manage` through Authorization
Services, externalize the authorization form, and retain it until reply/timeout.
The helper reconstructs and checks the exact granted right without interactive
extension. It never accepts raw PF rules, paths or server configuration through
IPC. A separately compiled root provisioning utility can register only that custom
right as authenticate-admin; it refuses to overwrite an existing definition.
The provisioning utility is NOT run by build scripts.

## Operations

- Status: fixed backend argument `status`; actual read-back or error/unknown.
- Verify Administrator Access: validates management authorization only; no PF call.
- Enable/Disable: management authorization required; fixed backend arguments only.
- Refresh: helper serial timer every ten seconds; backend checks persistent intent
  so it cannot undo Disable. Refresh and user actions share serialization.
- Reconnect: explicitly unavailable until an authenticated user-session adapter is
  integrated. Root's VPN namespace is not assumed to equal the user's.

Fixed paths:
- `/Library/PrivilegedHelperTools/org.v2boxkillswitch.helper`
- `/Library/PrivilegedHelperTools/org.v2boxkillswitch.backend`
- `/Library/Application Support/V2BoxGuard/client-pin`
- `/Library/Application Support/V2BoxGuard/approved.json`
- `/Library/Application Support/V2BoxGuard/state/`

Helper validates root ownership, writable-mode restrictions, regular files,
non-symlinked parents and link counts before reading the pin/executing the backend.
Backend uses isolated Python, fixed trusted configuration/state paths, fixed native
commands and no shell. It refuses Enable when PF safety preconditions fail.

## Testing status

`bash menu-bar/test-security.sh` runs non-interactive pin-parser and invalid-form
length tests, not positive authorization/peer tests. The helper and client compile.
No services, rights or live PF rules have been installed by these checks.

`bash menu-bar/test-ipc.sh` builds/ad-hoc-signs and runs an unprivileged anonymous
IPC test executable: matching pins succeed, a mismatched incoming client cannot
invoke the exported method, and a mismatched server response is rejected. It does
not run the production helper, register a Mach service or request admin rights.

Root deployment, rights registration and first firewall activation require a
separate reviewed approval. Existing emergency disable limitations, IPC failure
recovery and interaction with unrelated PF owners still need independent testing.
