# Third live trial — limited IPv4 disconnection evidence

The user explicitly approved a controlled live activation and deliberate VPN
disconnection test. This is not production certification or publication approval.

## Preparation and journal reconciliation

- Baseline: VPN Connected, PF disabled, no PF states/skip flags, empty project
  anchor, and one matching live approved outer transport.
- Preserved the previous completed trial privately instead of overwriting it.
- Preparation refused Enable because the PF-token journal belonged to another
  boot. Diagnostics established exact schema, trusted metadata and token=null.
- Archived the failed unactivated preparation and its unloaded timer.
- Under the runtime lock, reverified Off/PF disabled/empty anchor, privately
  preserved and fsynced the OLD EMPTY journal, then wrote/read back a current-boot
  empty journal. No nonempty token was cleared, released or inferred stale.
- Fresh approval/syntax/preflight and baseline tunnel HTTPS passed. The independent
  test timer was staged before activation. No helper/app/backend update occurred.

## Connected test

Actual activation returned On with Disable available. The existing observer
reported `limited_ipv4_pass`, `limited_ipv4_checks_passed`, usable pinned tunnel
HTTPS and successful capture startup. Its strict evaluator accepted the evidence.

## Deliberate disconnection

A separate diagnostic captured probe/DNS packet headers on the active physical
interface before disconnecting. It revalidated real/effective UID/GID, permitted
supplementary groups, Aqua bootstrap and current console ownership before issuing
fixed user-session `scutil --nc stop/start` requests. It did not use root's VPN
namespace, the prototype worker or an installed automatic recovery runner.

Observed while Disconnected, including after an existing helper refresh interval:

- PF remained enabled immediately, after refresh, through probes and at test end.
- Interface-bound public TCP, public DNS and router DNS probes all failed.
- Owned default-deny counter increased **2 → 27**.
- Physical capture: **0 direct TCP probe headers**, **0 outbound DNS headers**,
  **0 kernel drops**.
- Router ping succeeded.

The diagnostic then explicitly requested reconnect as the logged-in user, without
removing PF. Native status became Connected. The first later pinned HTTPS check
was unusable; two subsequent checks were usable. Therefore Connected alone was
NOT counted as restored usable connectivity. No unprotected fallback was used.

## Final verified state

- Protection **On**, policy approved, exact canonical current kernel rules and
  root quick gate verified after reconnect.
- Menu Disable advertised available. A GUI Disable click was not exercised in
  this trial; prior trials exercised it, and helper-failure emergency GUI recovery
  remains missing.
- Completed timer exited after confirmation; its job was unloaded and startup
  plist removed, with PF rules and approval retained. There is no pending
  ten-minute quarantine timer from this trial.
- `/etc/pf.conf` hash remained
  `5c19552511b74875cbc78f63c1c4601db9292989003a83cdcd8065c9f2284e72`.
- Approval expires 24 hours after preparation. Expiry/network/profile changes can
  fail closed and interrupt connectivity; this was not permanent approval at
  trial completion. The user subsequently explicitly removed that active expiry;
  see [approval expiry removal](APPROVAL-EXPIRY.md).
- Persistent automatic reconnect is **not installed**. This was an explicit
  one-time diagnostic reconnect, not proof of an autonomous recovery service.
  Subsequently, a separately approved [app update](ON-UPDATE.md) installed the
  start-only opt-in feature without disconnecting V2Box. Its native automatic
  Start call remains live-untested; it is Off on app launch.

Private evidence remains under the installed first-test/state directories. Do
not publish captures, discovery/configuration or private backups.

## Limits

This was orderly native disconnection, NOT a forced provider/app crash. Header
capture covered the specified probes/DNS, not every conceivable bypass. IPv6,
network switching, sleep/wake, reboot/startup, helper death and long-term stability
remain unvalidated. Router admin and approved outer endpoints remain narrow but
intentional exceptions, not proof against a malicious proxy at those destinations.

The original second-trial outage is still unexplained. An older-boot EMPTY journal
blocked this preparation; that does not establish the cause of the historical
outage. Empty-journal manual reconciliation is not a general boot protection or
nonempty-token reconciliation implementation. Public release remains withdrawn.
