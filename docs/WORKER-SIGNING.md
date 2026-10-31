# Worker artifact and connection signing boundaries — source only

New source files:

- `menu-bar/Security/WorkerArtifact.swift`: prelaunch file/signature policy.
- `menu-bar/Security/RecoveryPeer.swift`: accepted-XPC-connection role policy.

Neither is integrated into the installed helper, a recovery runner or the worker's
stdin/stdout control channel. No new service, endpoint or command is exported.

## Prelaunch artifact policy

The production `WorkerArtifact.validate(url, pin:)` has NO owner override. It requires:

- Root-owned, non-symlink ancestor directories, no group/other write permission,
  and search permissions for a worker launched under a non-root user.
- A root-owned regular single-link file, exact permission bits 0755, no setuid/gid
  bits, symlink or writable-file permission.
- No allow ACL entries on the file or ancestors, even if POSIX mode bits look safe.
  Deny-only ACLs are accepted; unsupported/unreadable ACL state is rejected. Darwin
  reports ENOENT for absent extended ACLs too, so unchanged lstat identity is required
  to distinguish that from an object disappearing.
- Strict static signature validity against the EXACT trusted local CDHash pin.
- Hardened runtime and no entitlements (including no debugging, JIT, DYLD or library-
  validation exceptions). This standalone worker needs none.
- Unchanged device/inode/owner/mode/link-count/size and modification/change times
  across signature checks.

This is not a process authentication lease. Trusted root updates must still be
serialized, and the exact approved path/pin must come from protected configuration,
not RPC fields. The current build is native-architecture and ad-hoc signed; no
Developer ID subscription is required. Other architectures/releases are unverified.

For unprivileged tests ONLY, a separate compile-time `WORKER_ARTIFACT_FIXTURES` entry
point permits the current non-root owner. It is absent from production compilation.
A user-writable fixture passing that entry point is NOT a trusted root artifact.
The production entry point rejects the actual user-owned development worker.
No worker has been copied into a root-owned location for this validation.

`build-recovery-worker.sh` now signs the local read-only worker with hardened
runtime and no entitlements. This changes only an ignored build artifact. There
is still NO scutil/VPN execution path in that worker.

## Live signing must use the connection, not a PID lookup

`RecoveryConnectionPeer` is an exclusive alternative to `SessionPeer`, for an
ACCEPTED listener connection before resume. It captures kernel-derived UID/PID
and installs Foundation's exact signing requirement once. Foundation checks each
incoming message, avoiding a PID-based `SecCodeCopyGuestWithAttributes` lookup.
Construction only ARMS that policy; it does not prove the peer matched it. Never
resume a child, clear a fence or mark a peer ready merely because initialization
returned. Authorization may advance only from a Foundation-validated message.

Roles are fixed locally:

- `privilegedParent`: kernel UID must be zero.
- `userWorker(uid)`: expected non-root UID must be valid and exactly match.

Roles/pins are not client-supplied authentication fields. Captured PID is only a
correlation input for the independent observer, never signalling authority. Do not
use the pre-resume UID getter on an unestablished OUTGOING connection or compose
multiple signing-requirement setters on the same connection.

The peer's live code identity still needs binding to the known launch chain,
expected birth data, pending ticket, console/session and full enforcement context.
A matching signature/UID alone does not prove that this is the worker launched for
our ticket. An unprivileged user can run another copy of approved code.

## Validation actually performed

```sh
bash menu-bar/test-worker-signing.sh
```

The test first typechecks the production API without the fixture flag. It then
builds/signs a separate test binary and local artifact copies. Fifteen checks
cover valid exact pins, wrong pin, rejection of development files by production
root policy, missing runtime, debugging entitlement, writable/setuid/nonexecutable
modes, file/ancestor allow ACLs, symlink, hardlink, writable ancestor and changed
signed content. ACL changes affect only newly created private test copies/directories.

Seven anonymous IN-PROCESS XPC checks cover the valid worker role, wrong client
pin rejected before dispatch, wrong expected server pin, wrong UID, invalid worker
UIDs and rejection of a non-root process claiming the privileged-parent role.
Kernel PID capture is compared with the actual in-process sender PID. A client
rejecting the server's reply is not proof the server never dispatched; privileged
operations must enforce the caller requirement on the ACCEPTED server side.

These checks are unprivileged. No positive root-owner artifact or root-parent
connection, cross-process production channel, worker-crash recovery, service
registration, installation, PF write, network probe or VPN command is tested.
The 30 native worker tests also pass with the hardened read-only build.

## Remaining bridge work

Connect an authenticated native channel to the already staged child/witness gate,
bind the actual launch and kernel identities, supply full fresh authorization and
aggregate deadlines, and implement conservative restart reconciliation. Anonymous
XPC endpoints must be transferred through an IPC mechanism that carries Mach port
rights; serializing an endpoint's archive to ordinary pipe bytes is not by itself
a valid cross-process capability transfer.

No worker listener or helper rendezvous was added here. Any deployment or live
protection/recovery trial remains subject to separate approval. Installed diagnostic
app/helper, protection settings and trial-timer absence are untouched.
