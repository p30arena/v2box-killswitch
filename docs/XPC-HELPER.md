# XPC UI/helper boundary — client scaffold only

`menu-bar/Sources/V2BoxGuardClient/main.swift` is an unprivileged AppKit client
for the fixed Mach service `org.v2boxkillswitch.helper`. It has no shell fallback.
Without the helper it displays ERROR/UNKNOWN and disables all actions. The client
is not an enforcement mechanism and should not be trusted to determine PF state.

## Not implemented

There is no XPC listener, privileged daemon, service registration, operational PF
backend, or authenticated caller validation. Security utilities are implemented
but not integrated into a server. Never register an arbitrary listener under this
name or run the client as root.

## Implemented security utilities

`menu-bar/Security/PeerSecurity.swift` validates exact 40-hex CDHash pins and sets
`NSXPCConnection.setCodeSigningRequirement`, available on macOS 13+. This API is
confirmed in the installed macOS 13.3 SDK header. An exact locally approved build
can be pinned without a paid Developer ID account. Updates require explicit
repinning; ad-hoc signing is not a substitute for a reviewed distribution process.

The client now refuses to connect without a valid `GuardHelperCDHash` in its bundle
metadata and pins the helper before resuming a privileged Mach-service connection.
The package script deliberately supplies no pin: no trusted helper exists yet.

ManagementAuthorization validates an external Authorization Services form and
requires the exact custom management right. The future installer must explicitly
register that right as authenticate-admin; UI acquisition and listener integration
remain unfinished. No authorization rights are registered by this code. The
helper must apply a pinned client requirement too; one-way authentication is not
enough.

`bash menu-bar/test-security.sh` compiles and runs 12 pin-parser/invalid-length
checks. It creates no XPC connection, listener, authorization prompt or PF command.
These checks do not validate the positive authorization flow or live peer identity.

## Required helper security review

- Use a launchd Mach service with a fixed service name and a narrowly constrained
  code-signing requirement for approved client identity. Evaluate audit tokens and
  validate code-signing identity on every connection; do not trust a claimed PID,
  bundle ID, or caller-supplied path.
- Require administrator authorization for privileged transitions using Apple's
  supported authorization mechanism. Define and test rights, prompt lifetime,
  revocation, and denial behavior.
- Expose only fixed typed methods: status, enable using an already approved local
  policy, disable this project's anchor, and reconnect the registered VPN.
  No arbitrary commands, paths, PF text, interface strings or endpoint addresses
  arrive from UI requests.
- Serialize operations in the privileged service. Persist disable intent before
  removing our anchor. Refresh/restart must respect it. Do not use `pfctl -F all`
  or global `pfctl -d`; preserve other PF owners and anchors.
- Replies must be derived from fresh kernel/service state, indicate stale/unknown
  explicitly and never claim success based on command exit status alone.
- If a client disconnects mid-operation, the helper completes or rolls back to a
  known state and reports the actual result on the next status request.
- App and helper signing, notarization, update, migration, uninstall, launchd
  registration, and macOS-version compatibility have to be tested before release.

## Local non-installing compile

`bash menu-bar/package-client.sh` builds an uninstalled app bundle in ignored
`.build`. Do not launch it expecting controls to work; no service is provided.
