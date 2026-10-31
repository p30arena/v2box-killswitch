# User-session recovery orchestration — offline prototype only

`src/session_recovery.py` composes the existing recovery state machine, a scoped
user-session VPN command adapter and an optional bound health probe. It has no
entrypoint, default runner, scheduler, launch agent or native transport. It is NOT
wired into the installed app. This privileged/brokered reconnect path remains
unavailable; the installed app's separate start-only convenience is described below.

Current reduced-scope work uses [app-session start-only reconnect](APP-AUTO-RECONNECT.md)
instead. It needs no privileged executor and cannot change PF or stop a VPN; a
submitted user request may finish after Disable. This broader stop/restart model
is not a prerequisite for that convenience and remains unwired.

## Evidence contract

The future pinned/authenticated native bridge must supply a fresh `RecoveryView`.
Constructing that Python dataclass is NOT authentication. A legacy status reply
with `state=on` cannot be converted to a permit without additional verification.

A usable view requires:

- The exact locally approved service UUID, matching the command adapter.
- Persisted enabled intent, enabled PF, verified first quick gate, and a complete
  match to the current approved policy; all flags must be actual True booleans.
- Approved mode, never quarantine.
- A stable opaque policy epoch covering intent/configuration/enforcement identity.
- For a present tunnel, a separately verified opaque connection identity, NOT
  merely the utun name. Reuse of a utun name must invalidate old health evidence.

The installed backend does not yet supply that complete contract. If the bridge
cannot establish either identity it must return unavailable, not invent an epoch.
No root API capability or menu reconnect action was enabled by this prototype.

## Worker behavior

Only `tick` is the supported orchestration entrypoint. Native callbacks must run
on one serialized worker, not the GUI thread. Recursive/concurrent ticks return
busy without launching a second action. Invalid/backward monotonic time is
rejected before callbacks. No PF operations or global networking changes exist.

The controller rereads the context around status/probe sampling and immediately
before each command, rechecks local status and target service, and drops stale
health/transition evidence after observed policy or connection changes. Retry
budget and backoff survive those changes to avoid unlimited retry bursts.

Observed Disable, lost helper trust, quarantine, mismatched service, malformed
flags or unverified policy prevent VPN command execution. Disconnected recovery
does not send health probes. Connected restarts are OFF by default and send no
probe traffic unless explicitly configured. Enabling those restarts requires a
bound probe, repeated unusable samples and fresh context checks. A single target
outage is not proof of a generally unusable VPN; production health policy still
needs review and live validation before allowing destructive automatic restarts.

The underlying recovery core also now checks enforcement before accepting a
healthy sample, so unverified evidence cannot reset its retry budget.

## Critical integration blockers

Fresh checks are NOT an atomic command lease. Disable can commit after the final
read but before an unprivileged native command starts. Future command adapters
must route authorization through the [broker](RECOVERY-BROKER.md), not execute
from a stale view. That broker now distinguishes protection intent from a prior
VPN operation that may still finish: pending state blocks new recovery, not
explicit authorized protection Disable. These components are not integrated with
the live intent writers. Do not promise live ordering or deploy this prototype
on the basis of these unit tests.

A production bridge also needs authenticated peer checks, stable policy/tunnel
generations, aggregate callback deadlines, worker cancellation, lifecycle handling,
and end-to-end verification in the actual logged-in session. No arbitrary commands,
paths, service identifiers or PF rules may become caller-selected root operations.
The root helper must not simply run the user's VPN commands as root.

The fake adapters exercise observed Disable at each revalidation boundary,
identity reuse, stale probes, unknown contexts, retry limits and worker reentry.
They do not prove transport authentication, macOS session behavior or race-free
command execution. No networking, deployment or activation occurs in those tests.

## Current machine

The previously approved diagnostic-only deployment is unchanged. Protection was
last verified Off, PF Disabled, project anchor empty, inventory absent and timer
unloaded. No recovery agent or new trial has been installed or prepared.
