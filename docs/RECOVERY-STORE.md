# Pending-command store — source only

`src/recovery_store.py` supplies the broker's previously missing file-backed
pending store. It is not instantiated by the installed runtime, timer or app.
There is no new executable, supervisor, agent or live recovery capability.

## Contract

The root integration must supply trusted boot identity, a fixed private state
directory with validated ancestors, and the SAME cross-process transaction used
by every intent writer. The store is NOT a mutex and has no execution authority.
Production expected owner defaults to root; a UID override exists for tests.

`recovery-pending.json` contains only version, boot identity, and either a pending
`ticket`/numeric `uid` pair or an explicit cleared value. It contains no command
line, service UUID, profile, endpoint, credentials, arbitrary output or PID.
Ticket generation must remain internal and collision-resistant, not caller-selected.

- Missing record means no fence and reading creates nothing.
- Unresolved same-boot tickets survive object and process reconstruction.
- A different unresolved ticket/user cannot overwrite an existing fence.
- Clearing requires the expected ticket AND user ID. There is no unconditional
  `write(None)` path. Clearing writes a tombstone atomically instead of unlinking.
- An unresolved other-boot record is never silently cleared, replaced or reused.
  Even a supplied matching completion cannot clear it through the ordinary API.
- A valid explicitly cleared record is not a fence after a boot change; read does
  not rewrite it. This says nothing about PF-token reconciliation or boot safety.

## File handling

The existing directory must have trusted ownership and exact mode 0700; the
store never silently creates it. The final directory component cannot be a
symlink. A held directory descriptor anchors reads, creation, replace, cleanup
and fsync, even if that pathname is subsequently moved/replaced.

Records must be regular, singly linked, expected-owner, mode-0600 files. Symlinks,
FIFOs, unsafe modes/owners, oversized data, invalid UTF-8, duplicate JSON fields,
unexpected schema fields, invalid tickets and invalid UIDs are rejected. Error
messages do not echo record contents. Corrupt/unsafe records are not repaired
or overwritten automatically.

Updates use an exclusive private temporary file, flush, file fsync, atomic
fd-relative replace, then directory fsync. Cleanup only unlinks a temporary that
this invocation actually created; a name collision does not delete someone else's
file. No glob-based cleanup, global rule operation or process signal exists.

## Error semantics

An exception does NOT prove a write rolled back. In particular, directory fsync
can fail after replacement. The broker therefore does not spawn after a pending
write error, and a new broker consults the on-disk fence rather than assuming the
failed call left no state. Clearing after verified completion can likewise report
uncertainty; callers must inspect state rather than invent a successful response.

The broker now uses compare-and-clear, including supervised reconciliation.
Its fake-store tests and real temporary-file integration tests cover the changed
interface, pending persistence, mismatched completion and failed commits.

A subprocess test writes, exits with `os._exit`, and a fresh interpreter reads the
fence. Fault-injection tests cover fsync/replace failures and fd-anchored path
replacement. These are NOT a power-loss test, actual reboot test, or proof of
all filesystem/storage guarantees. No actual VPN command or PF mutation occurs.

## Remaining blockers

This file is a FENCE, not a durable child-execution witness. A ticket alone cannot
identify, supervise or safely kill a surviving child after a helper crash. The
future trusted supervisor must persist and reconcile its own trustworthy lifecycle
information; missing child metadata alone is not proof that no command can start.
There is deliberately no age-based expiry or automatic reconciliation API here.

The broker now uses this fence only to pause NEW automatic recovery. Explicit,
authorized protection Disable does not read/clear or depend on this store; an
unknown or corrupt record must not create an indefinite menu lockout. A prior VPN
operation may finish later, but reconciliation cannot re-enable protection.

All-writer integration, pinned user-session execution, descendant supervision,
aggregate deadlines and helper-failure GUI recovery remain blockers. The installed
Disable and diagnostic-only deployment are untouched.
