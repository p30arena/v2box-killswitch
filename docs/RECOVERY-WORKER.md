# Read-only native recovery worker — not a VPN executor

`menu-bar/Sources/V2BoxGuardRecoveryWorker/main.swift` implements session identity
checks and a bounded pre-execution pipe handshake. It is not installed, registered,
packaged in the development kit, or called by the app/helper. This is NOT the
completed trusted supervisor. It has no scutil or other VPN execution path.

## Identity gates exercised natively

The worker rejects root/invalid target UIDs and requires:

- Both real and effective UID equal the expected non-root user.
- Real/effective primary GID match that user's account record.
- Current supplementary groups introduce no membership outside that user's
  account groups (missing memberships do not add privilege).
- `launchctl manageruid` match that UID and `managername` be Aqua.
- The current console user match the same UID.

The launchctl manual explicitly says `asuser` adopts bootstrap/audit context but
DOES NOT drop credentials. A future root launcher must establish both. These
checks do not implement the root-to-user launch itself or independently attest
all audit-session properties. They only verify the worker's observed identity.

Only two fixed read-only launchctl commands can be spawned. stdin is /dev/null,
stdout is captured privately, stderr discarded, environment fixed, and unrelated
FDs closed. Children are reaped before Ready. The worker clears an inherited
blocked signal mask and restores default SIGCHLD handling; it must not rely on a
PID after another component has reaped the child. On its diagnostic timeout, it
signals only its own unreaped child, not an arbitrary supplied PID.

Directory-service membership queries and kernel waits are not hard-real-time
operations. A future supervisor must supply an aggregate deadline, cancellation
and reconciliation; these identity checks alone do not guarantee GUI availability.

## Handshake

The read-only probe accepts `--probe-session <uid>`. The prepared handshake uses
only an internal ticket, UID, start/stop enum and registered service UUID. These
arguments are NOT authenticated XPC requests or proof of approval.

After identity checks it emits a bounded JSON Ready frame with `can_execute=false`.
It accepts one bounded ASCII control line on stdin:

- `CANCEL <matching-ticket>`: acknowledges cancellation and exits.
- EOF/partial frame followed by EOF: exits without execution.
- No grant within two seconds: exits without execution.
- Unknown verb, mismatched ticket, oversized input or extra frame: rejects.
- `GRANT <matching-ticket>`: reports `execution_disabled` and exits. NO VPN command.

The worker never prints service UUID, user name, group list, command output or
profile data. The identity-only child commands have finished before the handshake
starts. A future actual executor must revalidate identity at the execution boundary
and implement full descendant ownership/cancellation; killing a worker is not
proof about hypothetical future VPN descendants.

## Tests and build

```sh
bash menu-bar/test-recovery-worker.sh
```

This compiles the standalone prototype and runs 11 unprivileged native tests.
They passed in the current Aqua/console session, including a launch with inherited
blocked signals and ignored SIGCHLD. On a non-console/background session, positive
handshake cases are explicitly skipped because the worker must refuse that context.
These are read-only native identity checks, not fake-only tests or VPN validation.
No admin prompt, service registration, PF write, network probe, start or stop occurs.

## Still required before integration

- A root-owned/pinned worker artifact, authenticated broker path and sterile launch
  environment; never use the user-writable build artifact as a privileged executor.
- Correct root-to-user credentials AND bootstrap/audit-session launch.
- Durable supervisor/child lifecycle witness bound to the pending ticket, with
  restart-safe reconciliation. A fence alone is not a child identity.
- Actual fixed-command execution with ownership of every potential descendant,
  bounded cancellation, verified termination and no stale-PID signalling.
- Shared-lock/fence integration for EVERY intent writer and usable emergency GUI
  recovery. The existing Disable must not be replaced by a permanent pending latch.

The installed diagnostic-only deployment remains unchanged; reconnect remains
unavailable and no live trial is prepared.
