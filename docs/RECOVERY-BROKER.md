# Recovery broker and native identity binding — source only

No live reconnect capability is enabled. The installed helper/app are unchanged.

## Native identity binding implemented in source

`SessionPeer` installs the exact signing requirement on an accepted XPC connection
and captures its kernel-derived effective UID. Foundation checks the requirement
before dispatching messages. No caller-supplied UID or authentication boolean is
accepted by the native protocol.

The helper source now exports a separate connection facade per peer, retaining
that identity. All facades share ONE operations core/queue/timer, rather than
creating duplicate refresh timers per connection. Management authorization still
uses the existing admin right. The reconnect path additionally checks current
console-user ownership when dispatched, not merely at connection acceptance.
It still replies unavailable and never executes a VPN command.

Anonymous, unprivileged XPC tests exercise exact peer pins, actual connection UID,
matching owner, missing owner, root owner and a different owner. They do not
register the real helper, authenticate an administrator, or change networking.

## Offline ordering model

`src/recovery_broker.py` is an injected model, not a root runner or transport.

- Only start/stop requests exist; service UUID comes from fresh private approval.
- Context must identify the approved service and same non-root console user,
  with enabled intent and verified approved kernel policy, never quarantine.
- All participating operations share one transaction lock.
- A pending ticket is written BEFORE supervised execution is possible.
- The lock spans command execution and proof that the command/descendants cannot
  start later. A participating Disable either commits first and prevents the
  command, or waits for proven termination before committing.
- Timeout, exception, mismatched completion or pending-clear failure never count
  as successful completion. The pending fence prevents another command or a
  participating Disable until trusted reconciliation proves completion.
- An explicit nonzero exit with proven termination is a command failure, not an
  unresolved running process. It permits clearing the pending ticket.

Tests use fake executors, a shared thread lock, and an IN-MEMORY stand-in for the
pending store. Threaded tests demonstrate the ordering; reconstruction tests show
that the broker does not reset an existing fence. Neither proves crash durability
or any macOS child-execution behavior.

`Peer`, `Context` and `Completion` in this model are NOT authentication primitives.
They must eventually be constructed by trusted native/root components, never
parsed from caller-controlled XPC request/completion fields. In particular, a
signed user client claiming "finished" is not a supervised termination proof.

## Deployment blockers — do not replace working Disable with this model

The prototype can deliberately refuse Disable when command state is unknown.
That is a safety specification, NOT an acceptable completed GUI recovery path.
The installed Disable is untouched. Before any integration:

1. Implement a private durable pending store (separate from bounded diagnostics),
   persisted before any possible spawn and retained across helper failure/restart.
2. Implement a bounded, trusted supervisor that executes only fixed scutil
   operations in the correct logged-in user's credentials AND bootstrap session,
   never as root. Verify identity before exec; supervise all possible descendants.
3. Handle cancellation, cleanup and reconciliation without killing unrelated
   processes or trusting a stale/reused PID. A timeout alone is not termination.
4. Integrate EVERY intent writer, including backend Disable and independent test
   timer, with the same transaction/fence. They do not participate yet.
5. Keep the menu usable and provide a reviewed recovery path for unknown command
   state/helper failure; do not create a permanent lockout behind this fence.
6. Wire the per-connection native identity into broker context, establish aggregate
   deadlines and audit outcomes, then verify actual session behavior with separate
   approval. No root command path or recovery capability has been exposed yet.

Until those blockers are resolved, the existing read/check/recheck session
prototype still cannot promise atomic ordering with arbitrary Disable writers.
Do not treat these model tests as live-security proof.
