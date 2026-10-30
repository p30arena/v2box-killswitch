# V2Box Kill Switch for macOS

A small PF based egress kill switch and launchd recovery helper for V2Box’s macOS Packet Tunnel. PF blocks outbound traffic by default, permits loopback and the active V2Box tunnel, and allows only V2Box’s configured transport endpoint on active physical interfaces. A user LaunchAgent requests reconnection when macOS reports the VPN disconnected; a root LaunchDaemon refreshes the PF anchor as interfaces or the endpoint change.

This project uses undocumented PF integration points. Apple says PF is not a supported API, and network filter interaction may vary by macOS release. Treat the rules as a starting point for a controlled local evaluation, not a universal guarantee.

## Security behavior and limits

- The default rule blocks outbound IPv4 and IPv6. There is no general DNS exception.
- Loopback and V2Box tunnel traffic are statelessly passed so existing connections survive PF activation.
- The endpoint exception accepts established TCP flows and is bound to the physical interface. PF cannot restrict this IP/port exception to the V2Box process; other processes can connect to the same endpoint.
- If endpoint or interface discovery fails, the helper retains the previous rules. Stale endpoint rules can prevent reconnection while the default block remains in force.
- Reconnection checks macOS connection status, not end-to-end tunnel health. A hung session that still reports Connected may not be restarted.
- PF’s system configuration is loaded before launchd jobs, but PF may not be enabled until the helper starts. This leaves a possible early boot window. Reboot behavior must be tested locally.
- Local network access and captive portals are blocked except for narrow DHCP and IPv6 neighbor discovery traffic.
- This project has no paid dependencies. It requires macOS command line tools, Python 3, and the V2Box service registered as `V2BOX` by default.

## Repository contents

- `bin/pf-refresh.py`: root helper that discovers the V2Box endpoint, active physical interfaces, and V2Box-owned `utun`, then refreshes only this project’s anchor.
- `bin/watchdog.sh`: bounded native reconnect attempts after a disconnected status.
- `bin/status.sh`: concise VPN and PF status.
- `bin/diagnose.sh`: read-only interface, PF, and provider peer snapshot. PF details require `sudo`.
- `bin/test-firewall-block.sh`: sends direct IPv4, DNS, and (when routable) IPv6 probes while capturing a physical interface. Run only with a reviewed active policy. It uses PF counters and capture output; a counter increase can include unrelated drops, so inspect the capture too.
- `config/`: LaunchDaemon and LaunchAgent examples plus a placeholder PF anchor. Replace `V2BOX` in the plists if the Network service has another name.

## Install

Review every script and rule first. Keep a local Terminal available during activation. Save `/etc/pf.conf` and the current PF rules before editing. The anchor reference must appear in the filter section before Apple’s filter anchor:

```pf
anchor "com.p30arena.v2box-killswitch"
load anchor "com.p30arena.v2box-killswitch" from "/etc/pf.anchors/com.p30arena.v2box-killswitch"
```

Install the refresh script and anchor under root-owned paths, for example:

```sh
sudo install -d -o root -g wheel -m 755 /usr/local/libexec/v2box-killswitch
sudo install -o root -g wheel -m 755 bin/pf-refresh.py /usr/local/libexec/v2box-killswitch/pf-refresh.py
sudo install -o root -g wheel -m 755 bin/watchdog.sh /usr/local/libexec/v2box-killswitch/watchdog.sh
```

If `scutil --nc status` does not include the endpoint fields, create a root-owned endpoint file using `config/endpoint.conf.example` as a format guide. It must contain only the profile hostname and TCP port, for example `vpn.example.invalid 443` (replace with your own V2Box values). Install it with mode 600 under `/etc/v2box-killswitch/endpoint`. Never commit this local file.

Copy the LaunchDaemon to `/Library/LaunchDaemons/com.p30arena.v2box-killswitch.refresh.plist` and the LaunchAgent to `~/Library/LaunchAgents/com.p30arena.v2box-killswitch.watchdog.plist`. Make sure their program paths match the installed files. Add the anchor reference to `/etc/pf.conf`, then syntax-check without loading:

```sh
sudo pfctl -nf /etc/pf.conf
sudo pfctl -f /etc/pf.conf
sudo /usr/local/libexec/v2box-killswitch/pf-refresh.py --once
```

Load the services after reviewing the generated anchor and confirming you have a local recovery path:

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.p30arena.v2box-killswitch.refresh.plist
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.p30arena.v2box-killswitch.watchdog.plist"
```

Check `sudo pfctl -s info`, `sudo pfctl -a com.p30arena.v2box-killswitch -sr`, and `./bin/status.sh`. Do not test by disconnecting the VPN until direct physical egress probes are blocked and tunnel traffic succeeds.

## Uninstall

Boot out both launchd jobs, restore your saved `/etc/pf.conf`, and reload that restored file. Remove only this project’s anchor and installed files. Do not disable PF if another service may depend on it. Verify the remaining PF rules and enable state afterward.

## License

MIT. See [LICENSE](LICENSE).
