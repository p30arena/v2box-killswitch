# V2Box Kill Switch for macOS — WITHDRAWN / NOT SAFE TO INSTALL

> **Stop: this project has caused loss of all network connectivity on a real Mac. Do not install or enable it.** The earlier installation instructions were unsafe and are withdrawn pending a redesigned and independently tested implementation. If you installed it, use the recovery procedure below.

This repository is retained publicly to document the failure and prevent others from repeating it. It is **not a working or supported kill switch**.

## Current direction: unattended reconnect tracker, not a kill switch

The fixed-IP PF design has been rejected. The installed guard is intentionally
Off and its obsolete IP approval has been revoked. No further activation is planned.

A **separate, user-only V2Box reconnect tracker** now builds locally: native status
callbacks, a 500 ms fallback, immediate Start requests and indefinite capped retries.
It does not call the old helper or change PF. It has **not yet been installed or
validated through a live disconnect/reconnect**. See [tracker scope, checks and
limitations](docs/RECONNECT-TRACKER.md).

**Reconnection is not leak prevention:** real-IP exposure remains possible while
the tunnel is down. Connected status is not proof of usable/protected internet.

## Known failure modes

- The PF policy blocks essentially all outbound traffic except the active tunnel and a specific VPN transport peer. It also blocks ordinary LAN access (for example, a router at `192.168.1.1`).
- When the VPN provider changes the remote endpoint, an exception based on a previously discovered address can become stale. The VPN then cannot reconnect, while the default-deny rule blocks all other traffic.
- PF enable references (`pfctl -E`) are reference-counted. A plain `pfctl -d` may not release an enable reference held by another process. Persistent launchd jobs can also re-enable PF or reload rules after a manual recovery.
- The project’s endpoint parsing, service startup ordering, PF anchor interactions, and network-change handling have not been validated sufficiently across macOS versions. Syntax checks are not safety tests.
- There is no verified boot-time guarantee, no process-exclusive endpoint exception, and no proof of safe behavior for every V2Box configuration.

These are significant limitations, not acceptable caveats for a production kill switch. Do not use the scripts, sample rules, or install steps as an operational guide.

## If you already installed it and lost connectivity

Use a local console. This may disable other PF protections, so understand the impact before proceeding. First stop this project's jobs so they cannot reload rules:

```sh
sudo launchctl bootout system /Library/LaunchDaemons/com.p30arena.v2box-killswitch.refresh.plist
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.p30arena.v2box-killswitch.watchdog.plist"
```

Then, only if you accept disabling/clearing PF rules that may belong to other software, the broad emergency reset is:

```sh
sudo pfctl -F all -d
```

This clears PF rules and states and disables PF; it can affect unrelated firewall software. Verify the project jobs are removed or unloaded before reconnecting. Restore any saved `/etc/pf.conf` only after reviewing it. Do not blindly reload an old project configuration.

## Repository status

The scripts and configuration are preserved for incident analysis only. They are not endorsed for installation. Any future replacement must be designed and tested on supported macOS releases, include a reliable local rollback that accounts for PF reference counting and launchd persistence, handle endpoint changes safely, define LAN policy explicitly, and be reviewed before publication.

## Replacement development

Historical PF experiments, including installed limited trials, are documented in
[development status](docs/REDESIGN.md) and the [Disable failure](docs/DISABLE-FAILURE.md).
Earlier trial success did not establish reliability; a subsequent menu Disable
failure required user emergency intervention. The PF work and development kit are
retained for analysis, not deployment. The withdrawal warning remains in effect.
The standalone [reconnect tracker](docs/RECONNECT-TRACKER.md) is the new reduced scope.

## License

MIT. See [LICENSE](LICENSE).
