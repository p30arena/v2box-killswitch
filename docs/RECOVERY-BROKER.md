# Recovery broker and native identity binding — source only

No live reconnect capability is enabled. The installed helper/app are unchanged.

## Native identity binding implemented in source

`SessionPeer` installs the exact signing requirement on an accepted XPC connection
and captures its kernel-derived effective UID. Foundation checks the requirement
before dispatching messages. No caller-supplied UID or authentication boolean is
accepted by the native protocol.

The helper source exports a separate connection facade per peer, retaining that
identity. All facades share ONE operations core/queue/timer. Management still
requires the admin right. Reconnect additionally checks current console ownership
when dispatched, not just at connection acceptance. It still replies unavailable.
Anonymous unprivileged XPC tests cover peer pins and kernel UID/console-owner gates.

## Correct scope: Disable protection is not Disconnect VPN

An earlier model refused Disable whenever a pending command lacked termination
proof. That was too strict and could create the lockout the menu must prevent.
The model has been corrected BEFORE any deployment:

- A pending/unknown command fences NEW AUTOMATIC RECOVERY, not an explicit,
  authorized protection Disable.
- Disable uses the shared transaction and the normal controller: persist Off FIRST,
  then remove owned rules/references and verify. Enforcement failures propagate;
  never invent an Off response. It does not read or erase recovery pending data.
- A previously created VPN operation may still finish after protection is Off.
  Disable protection is not a promise to disconnect VPN or kill an unknown child.
- Once Off commits, the broker cannot authorize a new operation from that intent.
  Completing/reconciling an older ticket cannot re-enable protection.
- Recovery NEVER calls Disable automatically. Restoring direct access is only an
  explicitly authorized user decision, not an outage/timeout recovery mechanism.

A running transaction may still delay Disable until its executor returns; the
native aggregate deadline and safe timeout path remain integration blockers.
This correction removes the indefinite fence-based refusal, not every possible
helper/kernel availability problem. The installed Disable is untouched.

## Offline ordering model

`src/recovery_broker.py` is injected, not a root runner or transport.

- Only start/stop requests exist; service UUID comes from fresh private approval.
- The same non-root console user, enabled intent, and exact verified approved
  kernel policy are required. Quarantine does not permit recovery.
- All participating operations share one transaction lock. The pending ticket is
  durably written BEFORE execution is possible.
- The executor normally owns the command through proven completion. Timeout,
  exception, mismatched completion or uncertain pending clear leaves recovery
  fenced. It does not block explicit Disable or prove that a child is dead.
- A proven nonzero exit clears the ticket but is reported as command failure.
- Clearing/reconciliation requires matching ticket AND user ID; it never alters
  protection intent or grants connectivity.

Threaded fake-executor tests demonstrate command/Disable ordering. Other tests
cover explicit Disable with unknown/corrupt/other-boot recovery state and no new
operation after reconciliation while Off. Real temporary-file integration and
fresh-process reads exercise the [pending store](RECOVERY-STORE.md). These do not
prove power-loss durability, native descendant control or live session behavior.

`Peer`, `Context` and `Completion` are NOT authentication primitives. Trusted native
components must construct them, not parse them from XPC request/completion fields.
A signed user client claiming "finished" is not supervised termination proof.

## Remaining integration blockers

1. Deploy/integrate the private pending store separately from bounded diagnostics.
   It is only a fence. A separate [witness store/parent EXEC gate](RECOVERY-WITNESS.md)
   now implements source-only persistence ordering and broker completion handoff.
   Native observations/transport and restart reconciliation are not integrated.
   Missing witness data is NOT proof that nothing can start later.
2. Integrate a pinned, root-owned worker with the validated
   [read-only root-to-user launch](USER-SESSION-LAUNCH.md). The
   [native worker](RECOVERY-WORKER.md) now supervises fixed read-only fixtures,
   including suspended staging, explicit resume, cancellation and reaping. It
   deliberately cannot execute VPN commands or persist a root lifecycle witness.
3. Implement actual fixed-command execution under the correct user's credentials
   and bootstrap/audit session, descendant ownership, bounded cancellation and
   restart reconciliation without stale-PID/unrelated-process signalling.
4. Integrate EVERY intent writer with the same transaction and disabled-intent
   semantics. Runtime/timer do not use this broker yet. Never bypass menu recovery
   by making explicit Disable depend on a healthy pending journal.
5. Wire per-connection native identity, aggregate deadlines, audit/status and a
   usable helper-failure GUI recovery path before a separately approved live test.

Automatic recovery is still unavailable; no new root command path is exposed.
