# XPC UI/helper boundary — client scaffold only

`menu-bar/Sources/V2BoxGuardClient/main.swift` is an unprivileged AppKit client
for the fixed Mach service `org.v2boxkillswitch.helper`. It has no shell fallback.
Without the helper it displays ERROR/UNKNOWN and disables all actions. The client
is not an enforcement mechanism and should not be trusted to determine PF state.

## Not implemented

There is no XPC listener, privileged daemon, signed authorization requirement,
service registration, PF backend, or authenticated caller validation. Never
register an arbitrary listener under this name or run the client as root.

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
