# Revised trial workflow — limited IPv4 checks only

Prepared after the first trial's operator-triggered Disable. PF remains Disabled
until an explicit menu Enable action. Old evidence was archived, not deleted.

## Avoid dependence on chat timing

The independent observer now confirms only this LIMITED IPv4 trial when:

- Physical captures started and report zero kernel drops on captured interfaces.
- Required interface-bound TCP, public DNS and router DNS attempts all failed.
- No direct TCP-test or outbound DNS headers appear in those captures.
- Physical outbound VPN transport headers were observed.
- The default-deny counter increased by at least the number of attempted probes.
- Router ping and pinned tunnel-bound HTTPS succeeded.
- Under the backend serialization lock, enabled intent is still True, quarantine
  has not applied, configuration/network snapshot are unchanged, and fresh kernel
  rules exactly equal the approved canonical policy with PF enabled.

Missing evidence, reset counters, changed rules, packet loss, failed binding, or
operator Disable prevent confirmation. Confirmation does not modify firewall
rules, turn PF off, release tokens, change approvals or restart networking.
It only writes a root-private limited-scope marker for the one-shot safety timer.

If checks are inconclusive, no confirmation is written. The independent timer now
allows TEN minutes from activation before quarantine, not three. The user can
explicitly Disable sooner, accepting direct-connectivity risk. The timer still
waits up to 15 minutes for activation; after that window rearm before another test.

## Menu status

Opening the Guard menu refreshes actual backend status. New labels include:

- Trial: not started
- Trial: IPv4 checks passed (limited)
- Trial: inconclusive — review needed

Menu auto-enabling is disabled so backend capabilities are respected. The UI does
not claim the VPN is generally healthy or that IPv6/boot/recovery are verified.

## Limitations remain

This is not certification of all traffic, IPv6, reboot timing, crash recovery,
sleep/wake, arbitrary remote endpoint changes or other macOS versions. The test
inventory is temporary (24 hours). Approval expiry or unapproved endpoints fail
closed. User-session auto-reconnect integration is still incomplete. Public main
remains withdrawn; development changes are not a production release.

No automated confirmation code writes PF rules. The only deadline action remains
quarantine when confirmation is missing, never unrestricted internet access.
