# V2Box Kill Switch for macOS — WITHDRAWN / NOT SAFE TO INSTALL

> **Stop: this project has caused loss of all network connectivity on a real Mac. Do not install or enable it.** The earlier installation instructions were unsafe and are withdrawn pending a redesigned and independently tested implementation. If you installed it, use the recovery procedure below.

This repository is retained publicly to document the failure and prevent others from repeating it. It is **not a working or supported kill switch**.

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

An experimental replacement is being developed. See [development status](docs/REDESIGN.md)
and the [uninstalled development kit](docs/DEVELOPMENT-KIT.md). The client/helper/backend
Enable/Disable paths are implemented but have not been deployed or validated end-to-end.
Passing mock tests does not make them safe to deploy. The separate DEMO preview still
has simulated controls only. The withdrawal warning remains in effect.

## License

MIT. See [LICENSE](LICENSE).
