# Active approval expiry removed — explicitly approved

The user requested removal of the trial's 24-hour expiry. The active profile now
has `expires_at: null`: explicitly no time limit, not a far-future timestamp hack.
Existing numeric expiries are still enforced for other/timed approvals. Missing,
malformed, boolean and nonfinite expiry values are not silently permanent.

The active service, profile, revision and exact numeric endpoints/ports/protocols
are unchanged. There is no approval of a new server, no wildcard or DNS exception,
and no removal of the PF kill switch. The user is choosing to trust that exact
endpoint until explicitly changed/revoked, including the risk of future address
reuse. Invalid/unknown endpoint/profile/configuration still fails closed.

## Applied change

`tools/remove_approval_expiry_on.py --remove-expiry-on` is a narrow, explicit root
migration. It accepts only the known old and reviewed new endpoints-module hashes,
rebuilds the installed isolated zipapp with ONLY `endpoints.py` changed and verifies
all other archive members/entrypoint bytes. This does not relax the normal
On-updater's byte-identical filtering-module requirement.

Private backups were retained. Under the runtime lock, the existing helper was
briefly stopped, the compatible backend patched first, then only the active
profile's expiry changed to null. The same helper restarted. No app relaunch,
VPN stop/start, PF load/enable/disable/flush, intent or token write was requested.
The app's existing opt-in state was not reset by this operation.

The first attempt hit a concurrent read/status lock before staging or modifying
anything. Read-only retries are bounded; validation failures are not retried as
if permission had been granted. The subsequent authorized operation completed.

Post-change verification established approved **On**, Disable/auto-connect
capabilities available, unchanged kernel rules/intent/token/helper/PF config
across a helper refresh interval, and equality of all configuration fields except
the active expiry. The 24-hour cutoff no longer applies to this active profile.

## Limits and recovery

Caught critical-window failures attempt to restore the previous approval/backend
and restart the helper; they NEVER restore intent or modify PF. A post-change
verification failure keeps backups and requires review. This is not a durable
power-loss/SIGKILL transaction, reboot guarantee or independent emergency GUI path.
Do not rerun this one-time migration against an already-permanent/changed module.

Tests cover explicit permanent approval at a distant future time with identical
rules, malformed timestamps, unknown endpoints/profiles, runtime On/auto-connect,
archive-only changes, unrelated configuration preservation, atomic file writing
and bounded read retry. An actual candidate zip rewrite was also verified before
installation. No additional VPN disconnection/crash/IPv6/reboot test was performed.
Earlier trial/reconnect validation limits and public withdrawal remain unchanged.
