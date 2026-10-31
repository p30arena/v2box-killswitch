# Independent kernel process observer — read-only, source only

`src/process_observer.py` queries the public macOS `proc_pidinfo(PROC_PIDTBSDINFO)`
API directly in the parent, independently of the worker's staging report. No
process is launched, signalled, resumed, killed or reaped by this module. It is
not instantiated by the installed helper/runtime and has no exported XPC/CLI API.

## Checks implemented

- Positive bounded integer PIDs; malformed/coerced/zero/group IDs are rejected.
- Fixed Apple `/usr/lib/libproc.dylib` binding; supported 64-bit Darwin struct size
  and birth-field offset checked before use. Short/denied/missing reads fail closed.
- Repeated kernel snapshots must agree on PID/birth, parent and real/effective/
  saved UID/GID. Process names, argv and command output are never decoded/emitted.
- `verify_staged` compares the expected worker/child birth data against those
  snapshots, requires the expected live worker parent and actual child->worker
  relationship, and checks all six UID/GID credential fields against the target.
- The worker must be runnable/sleeping; the child must be stopped on EVERY sample.
  Child observations are bracketed with worker re-observation. Runnable/sleeping
  scheduling changes alone do not invalidate the worker identity.

The expected worker PID/birth and its parent MUST come from a trusted LIVE launch
chain. Do not reconstruct them from an old file, caller-provided PID, or a new
unrelated process. The launchctl/sudo monitor chain still needs explicit production
binding; this observer does not discover/authenticate that chain automatically.

## Deliberate limits

Repeated reads are consistency checks, NOT atomic leases, code-signing attestation,
or signalling capabilities. They do not prevent the process owner from changing
state immediately afterward. The observer cannot authorize recovery or clear a
pending ticket. Missing PID/permission/error are UNKNOWN, never completion proof.
It provides no restart reconciliation or descendant enumeration/termination.

BSD process info does not provide independent supplementary-group membership or
bootstrap/audit-session proof. Those, signed/hardened worker integrity, trusted
transport and exact fresh approved PF/intent/generation checks remain separate
requirements. A live process with matching credentials is not necessarily our code.
Fail-closed enforcement must never depend on a user process staying stopped.

The supported layout is the public proc_bsdinfo ABI used by this host's macOS 13
SDK. Runtime size/count checks and real native comparison passed on the current
Intel host; this is not Apple Silicon or other macOS-version validation. No private
kernel API, external package or non-system executable is needed.

## Validation actually performed

16 injected-reader tests cover identity reuse/change, parent/credential mismatch,
wrong state, unsupported platform/library failure, and failed/short/missing reads.
These tests do not perform real PID-reuse attacks or prove atomicity.

The native worker suite now has 30 tests. Four new read-only tests:

1. Independently observe the known worker and suspended child and compare actual
   kernel birth data with the staging report.
2. Reject wrong birth, expected parent or target user.
3. Reject a resumed fixture as staged.
4. Combine independent observation, the witness store and EXEC gate: persist a
   user-owned scratch witness before resuming the fixed identity fixture, observe
   its trusted-test reaping acknowledgement, persist completion and model broker
   clear ordering.

That paired test uses ONLY read-only id/sleep fixtures, an unprivileged temporary
state directory and fixture-only authorization. It does NOT attest a pinned/root-
owned worker, validate actual PF/intent approval, write installed root state or
exercise an authenticated production bridge. No VPN command, network probe,
registration, installation, reboot or protection activation occurs.

Next: authenticate/bind the actual native launch and transport, integrate full
fresh enforcement context and aggregate deadlines, and implement conservative
restart reconciliation before separately approved deployment/live testing.
