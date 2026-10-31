# Read-only authenticated endpoint handoff — source/test only

`menu-bar/Security/RecoveryHandoff.swift` adds a read-only rendezvous and one-shot
private endpoint confirmation. It has NO EXEC, VPN, PF, pending-clear, lifecycle
completion or generic command method. It is not wired into GuardProtocol, the
installed helper, the native recovery worker or the Python witness gate.

## Transport and identity

A bootstrap connection must already exist. Accepted connections arm Foundation's
exact per-message code requirement through `RecoveryConnectionPeer`, checking
kernel UID/PID against locally trusted expected live-launch identity. No authority
is granted merely on connection acceptance; acquire/confirm run only after a
Foundation-validated message.

The caller supplies only an opaque ticket. A trusted local launch validator is
rechecked, the deadline must remain fresh, and issuance is one-shot. The reply
carries an actual `NSXPCListenerEndpoint` through a typed XPC reply with an explicit
allowed class. It does NOT archive/serialize Mach rights into pipe bytes.

The private listener independently repeats code/UID/PID checks. The client must
pin its new connection too: receiving an endpoint is not server authentication.
The confirmation is read-only, rechecks launch context and consumes the handoff.
Replay, expiry, close or revocation refuse confirmation. One-shot state and
deadlines are IN-MEMORY, per instance—not a durable ticket fence or restart proof.
Reconstructing this object cannot authorize reuse, clear pending state or establish
that an earlier worker terminated. Tickets alone never identify a worker. The production expected PID must come from the actual supervised
launch, not a claimed field, stale file or another copy of approved code.

The launch validator here is not full recovery authorization. All-writer intent
ordering, exact fresh enforcement, console/audit context, process birth binding,
root artifact policy and lifecycle ownership remain separate requirements.
The endpoint deadlines do not make those checks atomic or certify GUI availability.

## Validation performed without registering a service

```sh
bash menu-bar/test-recovery-handoff.sh
```

Fourteen anonymous IN-PROCESS suites passed: successful transfer/confirmation and
replay refusal; wrong ticket, client pin, UID or PID; initial expiry/revocation;
wrong private server pin, private revocation/expiry/wrong ticket; pre-start clock
readings on both channels; and invalidation. Seventeen context-schema checks reject
malformed tickets (including trailing newline/Unicode), invalid UID/PID, lifetimes
and clocks.
Wrong client-pin/UID/PID cases never reach the launch-validation callback.

These exercise real Foundation endpoint marshalling, but do not prove cross-process
transfer, a root-parent peer, initial production rendezvous, or a supervised worker
connection. No registered Mach service, root operation or native command is used.

## Cross-process harness BUILT ONLY — run requires separate approval

Sources are under `menu-bar/CrossProcessFixture/`. The builder:

```sh
/usr/bin/python3 -I tools/build_read_only_xpc_fixture.py --build-only
```

compiles and hardened/ad-hoc signs a private local app with a bundled PER-USER XPC
service, verifies signatures and writes a build record under an ignored unique
`.build/read-only-xpc-*` directory. It does not execute/open the app, connect to the
service, register it, install files or modify startup/configuration. The parent
requires explicit `--run-read-only` and refuses root execution.

The two test binaries use exact mutual pins from an external user-owned fixture
config, avoiding circular bundle hashes. That config is NOT production trust.
The fixture binds the caller's live PID/birth, checks its kernel identity in the
service, transfers the endpoint through XPC, pins the private connection and checks
that the server PID is actually distinct and consistent. A second confirmation
must be rejected. An eight-second parent deadline and a fifteen-second service
self-exit watchdog bound the diagnostic attempt under normal OS operation.

Running it WOULD activate a temporary app-bundled user XPC service via launchd.
It is not a root helper/LaunchDaemon/LaunchAgent installation or startup item, but
macOS may retain ordinary app/service logs, caches or registration metadata. Normal
file-access prompts are possible. This is why running is not part of build-only
validation. Neither binary contains V2Box/scutil, PF or protection control.

At this commit the cross-process app/service has NOT been launched. Build/signature
success is not runtime proof. The next step is a separately approved, unprivileged
read-only diagnostic launch, then review of its result. A successful diagnostic
would still not authorize root worker deployment or a live VPN/protection trial.
