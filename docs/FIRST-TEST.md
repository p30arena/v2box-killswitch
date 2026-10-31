# First controlled test — activated, then stopped by operator

## Observed result

- Operator enabled through the menu; PF and backend both reported On.
- Operator confirmed internet worked; pinned tunnel health was usable and router
  ping succeeded. Direct TCP, public DNS and router DNS sockets failed.
- Physical capture had no direct test TCP or outbound DNS headers; transport
  continued. IPv6 was not tested.
- PF counter went from 3 to 2, so counter-based proof was inconclusive. The driver
  reloaded unchanged rules on each refresh, resetting counters. An idempotent
  replacement fix is now offline-tested in SOURCE ONLY, not applied live.
- Confirmation did not complete within the 180-second limit. The independent
  timer applied quarantine at 180.8 seconds. This caused the later internet block.
- Operator used menu Disable. Backend then reported Off and PF Disabled.
- Test timer was unloaded. Its startup plist remains pending privileged cleanup;
  do not reboot/re-enable for another trial without reviewing the test setup.

No successful all-scenarios validation or release claim is justified by this test.

## Historical preparation

The operator explicitly approved preparation and a controlled activation. Before
activation the following preparation was completed:

- Fresh root-private PF backups and endpoint/socket match.
- No PF states or skip interfaces at inspection.
- A pinned HTTPS baseline request bound to the V2Box tunnel succeeded.
- Proposed active/quarantine rules and root config passed native syntax checks.
- First quick project filter anchor attached with PF still disabled.
- Current matched endpoint approved for a 24-hour TEST inventory, not indefinitely.
- Independent root safety timer armed; a diagnostic observer waits for activation.

## Interactive activation

Use the menu Enable action, not an unreviewed shell command. Do not disconnect
V2Box during this first test. Observe whether ordinary internet continues and
report immediately. Administrator authorization is still required.

The safety timer waits up to 15 minutes for activation. Once enabled intent is
observed, it allows 180 seconds for confirmation. If not confirmed it persists
Disabled intent (stopping refresh) and loads quarantine without disabling PF or
releasing its enable token. Quarantine retains only loopback, narrowly allowed
router/bootstrap access and final outbound deny. This is NOT a connectivity
rollback: internet can remain blocked. Explicit menu Disable is the intentional
escape hatch permitting direct access, with its leak warning.

The timer is an independent one-shot LaunchDaemon, not the watchdog or chat shell.
It exits without changing rules if no activation occurs or the user disables.
Do not re-enable after the first test without checking/rearming the timer.

## Observer

The separate root observer waits for actual On status. It then starts header-only
physical captures, attempts direct TCP/DNS using Darwin IP_BOUND_IF=25 (confirmed
in installed SDK), checks router ping and tunnel-bound pinned HTTPS health, and
saves counters/results privately. A failed socket alone is not proof of blocking.
Capture startup, binding, rule counters and matching packet headers need review.
It never confirms the test or changes PF. IPv6 is NOT covered by this observer.

## Preparation fixes discovered on the real Mac

- The live root ruleset was initially empty, consistent with the earlier emergency
  flush, despite stock PF config on disk. Detached legacy anchors were preserved.
- macOS -sr includes scrub-anchor normalization before filter rules. The driver now
  ignores only normalization when locating the first filter; earlier actual
  pass/block/filter anchors are still rejected. Regression test added.
- Router exceptions narrowed to ICMP echo, TCP 80/443 and DHCP renewal. General
  router DNS access is no longer granted. Explicit broad LAN mode is not used.

## Scope

This is not proof of reboot protection, IPv6 safety, arbitrary endpoint rotation,
automatic profile selection or completed user-session reconnect integration.
The public withdrawal warning remains in effect pending validation/review.
