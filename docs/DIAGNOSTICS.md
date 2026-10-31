# Private failure diagnostics — local development deployment

Added after the second trial. The backend/helper/menu diagnostic update was
explicitly approved and installed while Off. No policy was installed, timer armed
or protection activated. These changes cannot reconstruct the earlier outage;
they instrument future backend decisions. The instrumented trial-timer script
itself remains source-only until a separately approved trial preparation.

## Stored evidence

`state/diagnostics.json` is a bounded, root-private JSON journal. Its writer runs
under the existing backend runtime lock; it does not install services or call PF.

Events contain only:

- Fixed operation, stage, outcome and reason enums.
- Sequence number, occurrence count and first/last wall-clock timestamps.

Stages distinguish interface/gateway/VPN/tunnel discovery, preflight checks,
approval validation, enforcement operations, and the two quarantine paths.
Successful refreshes record tunnel presence/absence, NOT VPN usability.

A failed discovery is recorded BEFORE fallback quarantine. A successful
quarantine is recorded separately and does not overwrite the original failure.
Failure to apply quarantine or complete Disable is recorded as failure, not
success. Approval rejection and approval-triggered quarantine have separate events.

The last 128 events are retained; consecutive identical events coalesce. A
separate last-failure entry survives successful recovery and history rotation.
Timestamps can move with the system clock; sequence numbers order events.

## Privacy and file safety

No exception text, native command output, endpoints, addresses, UUIDs, profile
names, configuration contents or credentials are serialized. All string metadata
is checked against fixed enums. Existing files are bounded and schema-validated;
unexpected fields are rejected, not copied forward.

The directory must be private and owned by the expected UID (root in deployment).
The journal must be a regular, singly linked, mode-0600 file. Symlinks, FIFOs,
untrusted ownership/modes and oversized files are rejected. Updates use a private
temporary file, fsync and atomic replacement. Callers serialize access with the
backend lock; this is not a tamper-proof log against root.

## Failure behavior

Diagnostic write failures never gate quarantine or Disable. Mutating replies
report unavailable recording without falsely declaring the protection operation
failed or successful. This does NOT mean a genuinely full disk cannot also break
other required persistence; tests isolate diagnostic failures from intent writes.

Normal status requests and Off-state refreshes do not append events. Status
returns a small allowlisted historical failure summary, never the full journal.
The source menu renders that summary without an administrator prompt and labels
it as historical, not a diagnosis of current connectivity.

The source helper no longer silently discards refresh errors. It emits fixed,
transition-only unified-log messages for unavailable backend calls, unavailable
diagnostic recording, and reporting recovery. Recovery is not a health certificate.

## Independent timer coverage

The source timer now uses the same private journal and runtime-lock ordering.
It records confirmation/Disable exits, activation timeout, deadline expiry,
syntax validation, persisted Off intent, quarantine command completion and marker
writing as distinct phases. A command's `ok` event means it returned successfully;
it is not independent verification of kernel enforcement or VPN health.

Fake-clock/fake-PF tests exercise ten-minute expiry without waiting or touching
networking. They cover confirmation and Disable at the deadline boundary, syntax
and apply failures, logging failures, and a marker failure AFTER a successful
quarantine command. Thus missing `fallback-applied` alone cannot rule out a timer
write. This does not establish that the historical outage used that failure path.

Future preparation refuses an older/mismatched diagnostics capability and requires
an actual atomic journal append under the runtime lock, rechecking Off intent,
before discovery or timer/policy staging. Readability alone is insufficient.

Deadline behavior is NOT changed: an unconfirmed active trial still quarantines
after ten minutes. No timer is currently armed; this instrumentation is not
permission to repeat a live trial or silently treat inconclusive evidence as pass.

## Limits before another trial

- Only the Off-state diagnostic deployment was approved. No new trial is prepared.
- Post-update verification checked Off/PF Disabled/empty project anchor, absent
  inventory and unloaded timer, exact backend source bytes, mutual code pins,
  and a successful private journal write/read-back. A second read-only check
  after the helper refresh interval again verified Off; /etc/pf.conf was unchanged.
- Native capture-statistic handling was checked while Off; no new active capture
  has been certified loss-free.
- No timer-quarantine marker was found for the second outage. Its cause remains
  unresolved; do not substitute the initial observer defect for an outage diagnosis.
- A process killed before it can record a failure may leave a started event and a
  helper-unavailable message rather than a complete private failure record.
- Failures before a trusted state directory/runtime lock is available cannot be
  journaled there safely; helper reporting remains limited to outcome unknown.
- `tools/verify_diagnostics_off.py --verify-off` performs read-only deployment
  checks. `--check-journal-write-off` additionally appends one private diagnostic
  event; neither mode changes PF, starts probes, installs policy or arms a timer.
- These events identify backend decisions, not every possible provider, transport,
  endpoint-change or application-routing problem. Tunnel presence is not health.
- Automatic reconnect, arbitrary endpoint updates, IPv6, sleep/wake and boot-time
  protection remain unverified/incomplete. Public release stays withdrawn.
