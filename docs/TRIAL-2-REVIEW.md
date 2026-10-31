# Second trial: stopped; later outage cause unresolved

The user reported usable internet and an inconclusive trial, then a later outage.
The user explicitly Disabled protection to restore access.

## Evidence from the initial observation window

- Bound physical TCP/public DNS/router DNS attempts: connection_failed.
- Default-deny counter: 4 before, 10 after.
- Direct TCP-test headers: 0; outbound DNS headers: 0.
- Outbound VPN transport headers: 1148.
- Tunnel-bound pinned HTTPS: usable; router ping: success.
- Capture kernel-drop count: unavailable, so confirmation was correctly withheld.

These measurements cover the initial window, not the later outage.

## Confirmed observer defect

The administrator launcher passes a blocked signal mask including SIGINT,
SIGTERM and SIGINFO. The observer inherited that mask and passed it to tcpdump.
Shutdown could therefore require SIGKILL without printing final capture stats.

The source observer now clears its own diagnostic thread's inherited signal mask
before spawning children and uses SIGINT for capture shutdown. Isolated child
process tests cover mask inheritance without root or network operations.

A native diagnostic AFTER Disable, with no PF changes or network probes, exited
successfully and printed packet/drop statistics after clearing the mask. Its
zero captured packets are NOT evidence about the active trial's packet loss.
The original capture cannot retroactively be declared loss-free.

## Do not invent an outage cause

The first explanation was the ten-minute quarantine timer, but cleanup found no
`fallback-applied` marker. That explanation remains unproven. At the time of the incident, the installed helper discarded refresh failures
with `try?`, leaving no durable incident history to distinguish transient
discovery/quarantine, tunnel failure or other causes after the observation window.
[Private diagnostics](DIAGNOSTICS.md) were subsequently added and installed
with separate Off-state approval. They do not reconstruct the missing incident
history; no new trial was prepared during that update.

## Verified cleanup

- Persisted intent Off; backend Off; PF Disabled.
- Project anchor empty (checked by the retirement tool).
- Timer unloaded; timer LaunchDaemon file archived/removed.
- Temporary approval archived privately; can_enable=false.
- /etc/pf.conf unchanged.
- No new activation or helper/backend deployment during cleanup.

The signal-mask observer fix is source-only; the separate native diagnostic was
run while Off. No further timed live trial is prepared. Public release remains
withdrawn. Automatic user-session reconnect, IPv6 and boot behavior are unverified.
