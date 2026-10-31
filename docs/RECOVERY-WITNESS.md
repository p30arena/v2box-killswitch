# Durable child witness and pre-EXEC gate — source only

`src/recovery_witness.py` provides a private boot-bound child-witness store and an
injected parent ordering gate. Nothing instantiates it in the installed runtime,
helper or worker. It is NOT an authenticated transport, kernel observer, native
executor, PID-signalling capability or completed restart-recovery implementation.

## Stored data

`recovery-child-witness.json` is separate from the pending fence, PF-token ownership
and bounded audit history. It contains only version/boot, ticket/UID, worker and
child PID/birth seconds/microseconds, phase and supervised exit code. No executable
path, argv, profile, endpoint, group list or credentials are stored.

The store reuses the pending store's private fd-relative JSON transport: caller-
validated ancestors, exact directory 0700/file 0600/trusted owner, regular single-
link file, no symlinks, bounded size, duplicate-key rejection, exclusive temporary,
file fsync, anchored atomic replace and directory fsync. JSON null is corrupt,
not a missing file. Public pending read/write/clear behavior is unchanged.

All callers must hold the SAME cross-process transaction as the broker and every
intent writer. Neither store is a mutex. No live root directory is selected or
created by default.

## Ordering

A future trusted native parent/adapter must:

1. Have the broker durably persist a fresh pending ticket before possible spawn.
2. Launch the pinned/root-owned worker in the validated user context and receive
   its suspended-child staging frame.
3. Independently kernel-validate worker/child identities, user credentials, parent
   relationship and worker code integrity. Reported PID/birth fields are NOT
   sufficient. An independent [read-only kernel observer](PROCESS-OBSERVER.md)
   now checks PID/birth, real/effective/saved UID/GID, parent and stopped state.
   Signing, supplementary groups, launch-chain binding and production wiring remain.
4. Call `WitnessGate.grant(identity)` under the broker transaction. It requires a
   matching pending fence and fresh injected authorization. It persists the
   `grant_recorded` witness, reads it and the fence back, and rechecks authorization.
   Only then does it return the bounded matching EXEC frame.
5. Send EXEC only on success. Any exception means NO EXEC, even if a renamed file
   is visible after a directory fsync failure. Cancel/close the staged worker's
   control channel and retain the fence until trusted reconciliation.
6. Following trusted native reaping/descendant-completion proof, call
   `WitnessGate.finish(identity, Completion(...))`. It validates the typed matching
   proof, commits `completed` plus exit code and checks read-back. It returns the
   proof only on success. The broker then performs its existing compare-and-clear.
   The gate itself never clears the pending file or changes protection intent.

The injected authorizer must independently re-read exact approved enforcement,
requested intent, console ownership and the expected policy/tunnel generations.
It must not be a caller-supplied boolean or a cached On view. Checks are not leases:
all-writer transaction integration is still required. No native XPC request or
caller claiming completion may construct trusted observations/proof directly.

## Conservative crash behavior

- `grant_recorded` means EXEC MAY have been sent; it does not prove execution began.
- A crash after witness persistence but before EXEC is conservatively unresolved.
- An unresolved witness cannot be overwritten with another ticket/process identity,
  reinterpreted on another boot, or expired by age.
- Identical grant retries re-fsync; visible data do not prove a failed sync succeeded.
  Retrying is only for the SAME still-owned staged child within its live transaction.
  A pending file after process reconstruction does not authorize spawning a new
  worker/child or reconstructing an execution lease. The broker refuses new requests
  while that fence is unresolved; native restart reconciliation is still missing.
- Completion is persisted BEFORE the broker clears pending. If clear fails, a fresh
  process can read the completed witness, but automatic reconciliation is not wired.
- Completed records cannot be downgraded to reuse the same ticket or change exit
  status. A new fresh ticket may replace completed history. The caller must generate
  fresh nonces; this single record is not a global history of every prior ticket.
- Worker exit, absent metadata, missing logs or PID absence are not accepted as
  completion proof by this module. It never signals a PID from a record.

PID/birth data are observational correlations, not atomic signalling capabilities.
Actual native descendant behavior and code integrity remain separate obligations.
Explicit authorized protection Disable remains independent of recovery-store health;
unknown recovery state pauses new automatic recovery, not menu Disable. Completion
while Off can clean up state but cannot re-enable PF or authorize another command.

## Validation and remaining work

26 new model/filesystem tests exercise persistence/read-back, authorization changes,
null/duplicate/malformed/unsafe files, directory replacement, sync failures before
and after rename, fresh-process reads, matching completion, and broker clear ordering.
The native worker suite now has 30 tests, including a paired read-only fixture
case that independently observes kernel identities and persists a temporary
user-owned witness before EXEC. Its authorization is fixture-only, not actual
PF/intent approval or signed-worker trust. No authenticated production bridge,
live root witness write, VPN action, reboot, worker-crash reconciliation or
power-loss proof is claimed.

Next: bind/authenticate the actual native launch and transport, then integrate
full enforcement context and this ordering with lifecycle ownership and EVERY
intent writer. A separately approved deployment/trial is still required. The installed
diagnostic-only app/helper, timer absence and protection settings are untouched.
