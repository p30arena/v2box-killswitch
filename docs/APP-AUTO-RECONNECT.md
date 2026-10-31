# Simple start-only app reconnect — installed, explicit opt-in required

This is the reduced alternative to a privileged recovery worker. The menu app
uses public SystemConfiguration APIs as the current non-root console user. No
subprocess, root reconnect RPC, worker broker, process supervision, launch agent,
PF change or VPN Stop/Restart is involved. The old recovery prototypes remain
unwired and are not prerequisites for this path.

## Behaviour

- Explicit opt-in, Off on each app launch; no persisted preference/startup item.
- Five-second status polling, with one helper status request and one native
  reconnect check in flight at a time. Native work is off the GUI thread.
- The signed helper status must advertise `can_auto_connect=true` and the exact
  `auto_connect_service_uuid`. The backend emits these only while requested
  protection is On and current kernel rules exactly match the approved policy.
  Off, quarantine, unknown approval, bad tokens and changed rules do not grant it.
- The app accepts only fresh (at most three seconds from reply receipt) evidence.
  A newer helper observation revokes older queued/in-flight decisions. This is NOT
  an atomic enforcement lease; PF protection is independent of this convenience.
- Bind to one service per opt-in. A target change latches a pause until the user
  toggles off/on. No service name, profile options, DNS bootstrap or endpoint
  exceptions are supplied by the app.
- Only Disconnected permits a start request. Connected is labelled **internet
  unverified**. Connecting/Disconnecting waits; after 30 seconds the display says
  stalled. There is no force-stop, connected-but-unhealthy restart or process kill.
- At most five start attempts per explicit opt-in, counted before submission,
  with 5/10/20/40/60-second cooldowns. Connected, missing status and policy churn
  NEVER replenish that budget. Toggle off/on deliberately rearms it.
- Native `SCNetworkConnectionStart(..., nil, true)` uses default options and
  linger=true so releasing the reference/quitting this app does not deliberately
  tear down a VPN. A true result is a submitted request, NOT usable connectivity.
- Confirming menu Disable clears opt-in immediately, before authorization or
  helper work. Turning the feature off never waits for the native worker queue.
  A previously dispatched request can still finish afterward; it cannot alter
  persisted protection intent, PF rules or references. Other writers' Disable is
  observed at the next status response, not through a shared transaction.

This is a best-effort app-session reconnect, not a security boundary, a startup
protector or proof of cleanup/termination. PF is the crash-leak enforcement. API
calls can stall on the background queue; UI cancellation remains independent, but
there is no claim of hard aggregate OS availability. Quit stops scheduling new
checks; an already submitted OS connection request may outlive the app.

## Disable usability fix

The client still waits for a Foundation-validated reply on the exact pinned helper
connection before sending sensitive authorization. Enable still requires a valid
positive capability response. A signed status error or `can_disable=false` no
longer vetoes an explicit authorized Disable attempt. The helper must still
verify the management right, persist Off first and report the actual result.
Status failure no longer hides the Disable menu action.

This does NOT create emergency GUI recovery when the helper is dead/unreachable.
No shell fallback exists. Running helper operations can still delay Disable.

## Validation and deployment limits

```sh
bash menu-bar/test-auto-reconnect.sh
python3 -m unittest discover -s tests
bash menu-bar/package-client.sh
python3 tools/build_development_kit.py
```

Tests inject the driver; no native VPN start occurs. They cover retry exhaustion,
backoff, unknown/transition states, target binding, monotonic time, no health-based
budget reset, default Off, stale/newer evidence, cancellation without waiting on
a blocked driver, and signed-reply preflight decisions. Python tests cover exact
live-policy capability publication and denial for Off/quarantine/expired approval,
modified policy, invalid UUID and pending token. A separate unprivileged native
read-only lookup actually reported the live V2Box service Connected. It did not
call Start and does not validate the new API's reconnect behaviour.

Following separate approval, the [On-preserving update](ON-UPDATE.md) installed
the app/backend/client pin and reopened only the Guard menu app. The helper binary
was retained. Approved On, Disable, the new capability, mutual pins and retained
protected state across a helper refresh were verified. No VPN stop/start or new
agent was requested. This is not a public release or general production certification.

Auto-reconnect is Off on app launch. The user must select **Automatically reconnect
V2Box (this launch)** in the Guard menu and confirm. Actual checkbox state was not
independently read. After installation, the user reported that reconnect works. This is user-observed
live confirmation, not an independently captured or instrumented automatic Start
test. No additional deliberate disconnect was performed. The earlier one-time
scutil reconnect remains separate evidence; neither establishes forced-crash,
IPv6, reboot or general recovery reliability.
The original updater is Off-only: do NOT run it against the active guard or
disable protection automatically to make an update possible. Independent helper-failure GUI Disable and reboot/network/
IPv6 validation remain open. The user subsequently explicitly removed the active
profile's [24-hour approval expiry](APPROVAL-EXPIRY.md). Its exact approved endpoint
now has no time limit; unknown endpoints/profiles remain blocked. Auto-reconnect
itself does not edit approvals. Public release remains withdrawn.
