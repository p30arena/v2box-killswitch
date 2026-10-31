# On-preserving app/backend update — approved installation completed

`tools/update_app_on.py` is a narrow alternative to the Off-only installer. It
updates only the backend, menu app and client pin. It does not replace the helper
binary, launch plist or authorization-right registration; launch new services;
run VPN commands; enable auto-reconnect; or launch/quit an app.

## Explicit modes

- `--check-only`: privileged READ-ONLY preflight, no staging or artifact updates.
- `--update-on`: separately approved installation. Never invoke automatically.

The actual installed setup passed check-only: exact approved On enforcement,
matching existing app/helper pins, and identical filtering/ownership modules.
The user then separately approved installation and reopening only the Guard menu
app. The update completed; it was not permission to disconnect V2Box, opt into
auto-reconnect, force a crash or conduct another live disconnection test.

## Checks and retained state

The candidate must have byte-identical `__main__`, controller, policy compiler,
PF driver, token store, endpoint/gateway validation and backend API modules.
Runtime status metadata changes are allowed; the comparison does NOT formally
prove all runtime semantics identical or replace source review. Duplicate ZIP
entries are rejected. Unknown/missing modules fail rather than being bypassed.

Preflight brackets backend status with a frozen comparison of kernel root/anchor
rules, enabled PF, exact On intent, approval, PF-token record, `/etc/pf.conf`, and
helper binary/plist identity. Existing helper launch arguments/services and
mutual code pins must match. There are no global state flushes or token releases.

A root-private candidate/backup stage is prepared while the helper still runs.
The app is re-signed against the CURRENT installed helper's exact hash, not the
development kit helper. Its new exact client pin is generated locally. This avoids
installing the unrelated helper/worker prototypes. Signatures and filtering-module
compatibility are checked again after copying.

Under the existing runtime lock, the tool rechecks retained state, unloads the
existing helper, swaps only the three artifacts, verifies retained state between
steps and restarts that SAME helper to reload its client pin. Native PF remains in
the kernel, independent of helper availability. The tool itself only issues PF
read queries; the restarted helper later runs its existing normal refresh.

After releasing the runtime lock, the updated backend must report verified On,
Disable available and the new auto-connect capability. Protected state and pins
are checked again. No authorization form is stored or new connection started.

## Failure behaviour and limits

- Preflight/staging failure does not unload the helper or replace installed targets.
- Caught failures inside the swap window restore artifacts and attempt to restart
  the old helper. An ambiguous bootout result still attempts service restoration.
- Rollback NEVER writes the saved intent/approval/token, reinstates PF rules,
  enables PF or undoes a concurrent explicit Disable. If protection changes, the
  update fails instead of forcing the baseline back into place.
- A post-swap verification failure retains the updated artifacts and all backups,
  reports failure and requires review. It does not guess that rollback is safe or
  disable protection to restore connectivity.
- A SIGKILL, OS crash, power loss, failed rollback or restart failure can leave
  mixed artifacts/helper unavailable. There is no durable update transaction or
  reboot guarantee. Backups are retained; independent emergency GUI recovery is
  still missing. Model tests are not an actual authenticated update integration.
- While the helper is stopped or the runtime lock held, menu operations can fail
  or require retry. Do not change VPN profile/network or protection during this
  short, explicitly approved maintenance window. No hard availability SLA exists.
- Existing endpoint approval expiry is unchanged. This is not a renewal tool.

The running old app will no longer match the new helper client pin. A separately
approved quit/reopen of the menu app is needed after success. Closing that app does
not remove PF protection. Auto-reconnect is Off on the new app's first launch;
its opt-in live behaviour still needs explicit testing, not inferred from tests.

## Validation performed

Injected filesystem/launchctl tests cover successful artifact replacement,
changes at every protection checkpoint, preserving a concurrent Off decision,
ambiguous bootout, missing staged files, bootstrap failure, interruption, exact
module comparisons and read-only PF query shape. No real service/PF/VPN operation
occurs in these tests. An additional unprivileged temporary staging fixture
actually copied/re-signed the development app and verified its patched helper pin
and resulting client signature; no installed path changed and no app launched.

The privileged check-only preflight passed against the active installed guard.
After explicit approval, `--update-on` completed and the user-session Guard menu
app was quit/reopened. Post-install verification established:

- Backend bytes exactly match the reviewed candidate.
- Current app/client pin and retained helper/app helper pin match.
- Verified approved On, Disable available and auto-connect capability advertised.
- Protected state remained identical across a subsequent helper refresh interval.
- The menu app is running; `/etc/pf.conf` is unchanged.
- No VPN stop/start, approval renewal, native worker installation or new agent.

The backup is retained privately. Actual menu checkbox selection was not read;
auto-reconnect starts Off by code and must be explicitly enabled by the user. The
new automatic native Start API has NOT been live-tested. Source/model tests and
installation verification do not prove that request succeeds for this provider.
The existing Off-only updater remains unchanged and must NOT be used while On.
