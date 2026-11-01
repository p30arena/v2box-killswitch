# Standalone V2Box reconnect tracker — NOT a kill switch

## Scope and current status

The user replaced the kill-switch requirement with fast, unattended disconnect
tracking/reconnection. This is a separate user-session app, not another PF design.
The obsolete installed IP approval has been revoked/preserved privately after
verified intent Off, PF disabled and an empty project anchor. No PF/token/VPN
operation was used to revoke it. The old helper remains installed; the new tracker
does not call it. Do not reactivate the withdrawn PF guard.

**Installed and running after explicit user approval.** The user-only app and
LaunchAgent were installed using the command below; launchd reported running,
one launch and no exit on a subsequent check. The installed signature verified.
No persisted Pause setting was present, so automatic reconnect defaults On.
The old user watchdog was preserved privately and unloaded to avoid competition.
No PF/helper/intent/token changes or deliberate VPN disconnection were performed.

A separate read-only diagnostic successfully discovered the local V2Box service,
observed its native state and registered the native event subscription. It could
not call Start. That diagnostic is not instrumentation of the running app's
callbacks. Successful subscription is not a measured disconnect latency or an
end-to-end reconnect test. Future-login, crash-restart and real reconnect behavior
have not yet been live-validated.

## Detection and automatic action

- Subscribe directly to `SCNetworkConnection` changes using
  `SCNetworkConnectionSetDispatchQueue` on a user-initiated serial queue.
- Process a notification immediately: no helper/status refresh interval, timer
  debounce, confirmation dialog, root escalation or IP inventory in this path.
- Read the current native state before acting, rather than trusting an old event.
- Nominal 500 ms polling fallback (20 ms timer leeway) even if events are unavailable
  or missed. This is **not a hard deadline**: macOS reporting, scheduling and sleep
  determine when the tracker actually gets to observe a change.
- On observed Disconnected, immediately submit `SCNetworkConnectionStart` with no
  profile/options override and `linger=true`. Recheck current console-user identity,
  pause state and Disconnected immediately before submitting.
- Retry after 250 ms, 500 ms, 1 s, 2 s, then at most once every 5 s indefinitely.
  A due retry runs on an event or the next fallback tick, not a separate busy loop.
  No five-attempt cutoff, exhausted budget, prompt, or per-launch opt-in reset.
- A new drop after Connected bypasses the old failure cooldown, with a 250 ms
  anti-spin floor. Fifteen seconds of Connected resets the retry rate only; it is
  **not an internet-health test**.
- Check immediately on initial attachment and wake. Activity prevents App Nap
  while awake but explicitly permits normal system sleep.
- Start-only: never stop/restart a connecting/connected VPN. A permanently stuck
  Connecting/Disconnecting state, silent data-plane failure while status remains
  Connected, or interactive V2Box/OS authentication is not repaired by this version.
  The tracker itself never asks permission for each reconnect; it cannot bypass
  authentication that the OS/provider requires.

## Lifetime and UI

Automatic reconnect defaults On and remains On across launches unless deliberately
paused. A deliberate Pause persists; Resume requests an immediate state check.
Already submitted OS requests can finish after Pause. The tracker cannot cancel
those by stopping the VPN. A per-user process lock prevents duplicate watchers.

The menu reports native status, whether event subscription succeeded, and a clear
warning that direct traffic may be exposed. Connected explicitly means internet/IP
protection **unverified**. Optional notification permission never gates monitoring
or reconnection. Notification rejection does not disable automatic reconnect.

The optional user LaunchAgent starts at login and restarts after abnormal exit,
with five-second launchd crash-loop throttling. Ordinary Quit stops tracking until
it is reopened or the next login and leaves V2Box running. It is not a pre-login
system daemon, and cannot reconnect while the computer/network hardware sleeps.

There must be exactly one discoverable V2Box service at attachment. Discovery uses
only Apple's fixed read-only `scutil --nc list`, with the V2Box provider identifier;
no shell, profile export, upstream address or credentials. Missing/invalid services
are rediscovered with a one-second rate limit and a two-second query timeout.
Multiple services are reported as ambiguous; no arbitrary profile is started.
An active selected service remains bound until it becomes invalid or the tracker
restarts; automatic live profile switching is not implemented.

## Build and checks (no installation)

```sh
bash menu-bar/test-tracker.sh
bash menu-bar/test-tracker.sh --read-only-native
```

Build output: `.build/V2Box Reconnect Tracker.app`, ad-hoc signed/hardened, no
privileged helper or NetworkExtension entitlement required. Compilation/signature
and policy fixtures are not live reconnect, provider-crash or wake certification.

## Explicit user-only installation/start at login

After installation approval, as the normal logged-in user, never sudo:

```sh
python3 tools/install_tracker_user.py --install-start-at-login --archive-old-watchdog
```

This installs `~/Applications/V2Box Reconnect Tracker.app` and
`~/Library/LaunchAgents/org.v2boxkillswitch.reconnecttracker.plist`, and starts it.
The flag explicitly preserves/unloads the known old `com.ali.v2box-vpn-guard`
user watchdog to avoid competing reconnect agents at future login. It does not
uninstall the old root helper/menu app or modify PF/intent/token files. Installation
refuses occupied tracker destinations rather than overwriting a running app.
The installation and immediate launch were live-validated after user approval;
future-login and crash-restart behavior remain untested.

## Privacy limitation

This is availability automation, **not leak prevention**. Traffic can expose the
real IP between tunnel loss and detection, during reconnection, or during a silent
failure that native status does not report. Faster callbacks cannot eliminate that
window. No third-party HTTP/IP probe is issued, no health claim is inferred from
Connected, and no firewall protection is advertised.
