# Read-only native recovery worker — not a VPN executor

`menu-bar/Sources/V2BoxGuardRecoveryWorker/main.swift` implements session identity
checks, a pre-execution pipe handshake, and direct-child supervision for fixed
read-only fixtures in `ReadOnlyChildSupervisor.swift`. It is not installed, registered,
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
DOES NOT drop credentials. A [separate read-only root-to-user diagnostic](USER-SESSION-LAUNCH.md)
now validates an asuser/sudo launch arrangement with Apple system identity queries.
It does not launch/deploy this worker or provide a VPN executor. These worker
checks do not independently attest all audit-session properties.

Identity checks use only two fixed read-only launchctl commands. stdin is /dev/null,
stdout is captured privately, stderr discarded, environment fixed, and unrelated
FDs closed. Children are reaped before Ready. The worker clears an inherited
blocked signal mask and restores default SIGCHLD handling; it must not rely on a
PID after another component has reaped the child. On its diagnostic timeout, it
signals only its own unreaped child, not an arbitrary supplied PID.

Directory-service membership queries and kernel waits are not hard-real-time
operations. A future supervisor must supply an aggregate deadline, cancellation
and reconciliation; these identity checks alone do not guarantee GUI availability.

## Handshake

The read-only probe accepts `--probe-session <uid>`. The `--prepare` handshake uses
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

## Direct-child fixture supervision

The separate `--supervise-probe <ticket> <uid> identity|wait` diagnostic can run
ONLY `/usr/bin/id -u` or `/bin/sleep 10`. It cannot accept a caller executable,
argv, PID, process group, shell, service or VPN action. `can_execute=false` means
there is no VPN executor; this mode does execute the fixed read-only fixtures.

1. The parent sends a matching GRANT after Ready.
2. After a fresh session check, `posix_spawn` creates the fixture with
   `POSIX_SPAWN_START_SUSPENDED`. macOS documents that user-space execution,
   including dyld startup, has not begun.
3. The worker reports `probe_staged` with its exact child's PID and kernel birth
   seconds/microseconds. UID/GID and parent PID are checked through the public
   `proc_pidinfo(PROC_PIDTBSDINFO)` API. These are correlation data, NOT authority
   to signal an arbitrary process after restart.
4. A separate matching EXEC permits resume, after another session recheck.
   A future trusted ROOT parent must independently validate and durably record
   the child witness before sending EXEC. A source-only [witness store and parent
   gate](RECOVERY-WITNESS.md) and [independent kernel observer](PROCESS-OBSERVER.md)
   are now paired with this worker ONLY in an unprivileged read-only fixture test.
   [Artifact/connection signing policy](WORKER-SIGNING.md) is now implemented
   separately; trusted launch binding and an authenticated production adapter
   are not integrated.
5. EOF, cancellation, malformed control or a two-second missing EXEC cancels and
   reaps the suspended child. A running fixture has its own two-second deadline.
   Cancellation allows up to one additional second to observe actual reaping;
   inability to do so reports `supervision_unknown`, never termination proof.

Only the PID returned by this worker's own posix_spawn may receive SIGCONT or
SIGKILL. It is signalled only while still owned and unreaped, with default SIGCHLD
handling and sole wait ownership preventing PID reuse. Ownership errors latch
unknown; no later observation may restore signalling authority. No process-group
signal or caller-reported PID is used. Exit acknowledgements follow waitpid,
not merely a successful kill. Broken output is handled without skipping cleanup.

This is a cooperative diagnostic protocol, not an authorization barrier against
the user who owns these processes (that user can independently signal/resume them).
Do not rely on a stopped user process for fail-closed PF enforcement. Actual VPN
CLI descendant behavior, hardened worker integrity and restart recovery remain
unverified. Parent EOF while the worker survives is NOT worker-crash cleanup.
Killing the worker or losing its output is NOT proof the child terminated, and
must not clear a future pending ticket. No durable child witness is installed.
The per-stage deadlines are NOT an aggregate API/GUI availability guarantee.

## Tests and build

```sh
bash menu-bar/test-recovery-worker.sh
```

This compiles and hardened/ad-hoc signs the standalone prototype (no entitlements)
and runs 30 unprivileged native tests. Separate artifact/anonymous connection
signing checks run via `bash menu-bar/test-worker-signing.sh`.
They passed in the current Aqua/console session, including a launch with inherited
blocked signals and ignored SIGCHLD. On a non-console/background session, positive
handshake cases are explicitly skipped because the worker must refuse that context.
These exercise real fixed child launch/suspension, reaping after normal exit,
cancellation/EOF before and after resume, missing EXEC, malformed control, timeout,
and broken output both at resume and after start. A kernel ps state observation
confirms the identity fixture remains stopped before EXEC. These are not VPN,
worker-crash, reboot or general descendant-supervision validation.
No admin prompt, service registration, PF write, network probe or VPN command occurs.

## Still required before integration

- A root-owned/pinned worker artifact, authenticated broker path and sterile launch
  environment; never use the user-writable build artifact as a privileged executor.
- Integrate the validated credential/bootstrap launch arrangement with the pinned
  worker; review audit-session details. The identity diagnostic alone is not an executor.
- Integrate the source-only witness/gate and independent observer with signing,
  trusted launch/transport, full enforcement context and restart-safe reconciliation.
  A fence alone is not a child identity.
- Actual fixed-command execution with ownership of every potential descendant,
  bounded cancellation, verified termination and no stale-PID signalling.
- Shared-transaction/disabled-intent integration for EVERY intent writer and
  usable emergency GUI recovery. Pending state pauses new recovery, not explicit
  authorized protection Disable; an earlier operation may still finish.

The installed diagnostic-only deployment remains unchanged; reconnect remains
unavailable and no live trial is prepared.
