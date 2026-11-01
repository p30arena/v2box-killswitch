# Paused research: application-aware VPN firewall profiles

## Decision and live state

The user asked to document this investigation and return to it later. **Research
is paused; no firewall product or new enforcement policy was installed.**

The standalone reconnect tracker is installed/running, with automatic reconnect
On and login startup configured; see [tracker documentation](RECONNECT-TRACKER.md)
for validation limits. The withdrawn PF guard remains intentionally Off, and its
obsolete IP approval was revoked/preserved privately. Do not reactivate or extend
the fixed-upstream-IP design. The old privileged helper remains installed; the
tracker does not depend on it. PF token reconciliation and the historical
[Disable failure](DISABLE-FAILURE.md) are unresolved, not claimed fixed.

## Proposed reduced policy

The user proposed an outbound, application-aware firewall with two profiles:

| Native VPN state | Desired profile |
|---|---|
| Connected | Allow normal app traffic |
| Disconnected, Connecting, Disconnecting, Unknown | Permit V2Box/provider bootstrap and upstream traffic; deny other apps' direct internet traffic |

Transitions must be automatic and unattended, not ask permission each time.
Changing upstream IPs/ports/protocols must not require firewall exceptions.
An explicit manual restore-normal-access action must be reliable.

**This is best-effort mitigation, not a strict kill switch.** A packet may leave
between tunnel loss and restrictive-profile activation. Native status can remain
Connected during a data-plane failure. Fast callbacks do not make profile changes
atomic with tunnel disappearance. Boot/login, tracker/firewall failure, IPv6,
sleep/wake and network changes introduce additional cases requiring validation.

## Platform findings

- The built-in macOS Application Firewall primarily controls incoming connections;
  it is not the outgoing per-app policy engine needed here.
- macOS PF has packet/interface/address/port/state predicates and socket user/group
  matching in supported cases, not a reliable signed-app identity predicate.
  Socket-owner UID is not equivalent to V2Box identity. After-the-fact `lsof`
  correlations are not atomic enforcement and are unsuitable as the boundary.
- `iptables` uses Linux Netfilter and cannot enforce macOS host traffic.
- NetworkExtension socket filters expose `sourceAppAuditToken`; macOS 13 also
  exposes `sourceProcessAuditToken` for the process actually creating a flow.
  Delegated DNS/system-service traffic requires particular care.
- `NEFilterPacketProvider` receives the actual packet interface, but its published
  callback does not expose the socket-filter app audit tokens. The inspected SDK
  headers do not establish a supported, race-free composition for our full policy.
  This is an unproven implementation path, **not proof of universal impossibility**.
- Simply allowing V2Box and denying every other app can deny those apps even while
  tunneled: do not assume every inner flow is attributed to V2Box.
- `NETunnelProviderManager.loadAllFromPreferences` returns configurations created
  by the calling app. A standalone utility cannot assume it can change V2Box's
  owned configuration using `includeAllNetworks`/`enforceRoutes`. Those properties
  alone are not evidence of lifecycle-complete kill-switch behavior.

Apple references:
- https://developer.apple.com/documentation/networkextension/nefilterflow
- https://developer.apple.com/documentation/networkextension/nefilterpacketprovider
- Local NetworkExtension SDK headers inspected: `NEFilterFlow.h`,
  `NEFilterPacketProvider.h`, `NEVPNProtocol.h`, `NETunnelProviderManager.h`.

## Candidate findings at this research snapshot

### PureSnitch — not suitable in its shipping implementation

Repository README describing shipping v0.2.2 explicitly states:

- No shipping per-process kernel filtering: required NetworkExtension entitlement
  and provisioning are not present in that build.
- Monitoring uses `nettop` and `lsof`; this is observation, not per-app enforcement.
- PF output is Default-profile, host-wide deny rules for IPv4/CIDR/ports.
  Process-specific, allow, domain, IPv6 and non-default-profile rules are not emitted.
- Home/Public Wi-Fi/Lockdown profile labels are not enforced; automatic switching
  is not implemented.
- Signing/notarization is not equivalent to the missing NetworkExtension capability.

Therefore it does not solve either V2Box-specific exemption or our two-profile
switching requirement. Recheck future releases rather than treating this as a
permanent judgment of the project. The GitHub description/feature names alone are
insufficient evidence of shipping enforcement.

Sources:
- https://github.com/momenbasel/puresnitch
- https://github.com/momenbasel/puresnitch#what-it-does
- https://github.com/momenbasel/puresnitch#how-it-works

### LuLu — real per-app filtering/profiles; automation and revocation unresolved

Current documentation states profiles exist from v4.0 onward, containing separate
rules and settings. Switching is documented through the settings UI/status menu.
The product page advertises macOS 10.15+; exact release compatibility/support on
this Intel macOS 13 machine must still be checked before installation.

Source inspection pinned to **v4.5.3** found:

- `App/main.m`: command-line handling for installation/upgrade/uninstall/quit,
  not an established public profile-switch command.
- `App/XPCDaemonClient.m`, `Extension/XPCDaemon.m`,
  `Shared/XPCDaemonProto.h`: internal `setProfile` XPC operation.
  An internal method is **not** a supported external API or authorization for our
  tracker to call it. Do not bypass signing/peer checks or edit live rule files.
- `Extension/FilterDataProvider.m`: new-flow allow/drop decisions and handling of
  paused flows. This inspection did **not** establish revocation of already-allowed
  flows when a profile changes. Documentation says new profiles apply to future
  decisions; do not claim existing connections are blocked.
- Existing permissive fallbacks, delegated flows and default OS-required rules
  need explicit review against a V2Box-only restrictive profile. No blanket exemption
  for all Apple programs, shared DNS or system daemons is acceptable by assumption.

Sources:
- https://objective-see.org/products/lulu.html
- https://github.com/objective-see/LuLu/tree/v4.5.3
- https://github.com/objective-see/LuLu/blob/v4.5.3/LuLu/App/main.m
- https://github.com/objective-see/LuLu/blob/v4.5.3/LuLu/Extension/XPCDaemon.m
- https://github.com/objective-see/LuLu/blob/v4.5.3/LuLu/Extension/FilterDataProvider.m

### Little Snitch — compatible legacy version; switching details unresolved

Vendor legacy downloads explicitly list **5.7.6** as compatible with macOS 13
Ventura (and macOS 11–14). Current releases are not automatically appropriate for
this machine. It is commercial software.

- Version 5 documentation confirms profiles and automatic network-based switching.
  Profile-independent rules continue participating alongside the active profile;
  a restrictive profile must account for these, not merely add a deny rule blindly.
- A documented CLI exists, with Terminal access requiring explicit configuration;
  most commands require root. The published command list includes preference writes
  and model backup/restore, but does **not** establish a dedicated supported
  profile-switch operation.
- Do not assume a preference key, use GUI scripting, or repeatedly replace the
  entire configuration as a profile-switch workaround.
- Existing-flow revocation, VPN-transition timing and noninteractive supported
  control remain unverified. Vendor support/version-specific documentation is the
  next appropriate evidence source.

Sources:
- https://www.obdev.at/products/littlesnitch/download-legacy.html
- https://help.obdev.at/littlesnitch5/adv-profiles
- https://help.obdev.at/littlesnitch5/adv-commandline

### Vallum — preliminary only

The current vendor page advertises rule conditions based on network/interface
activity, but current Vallum 6 requires macOS 14.6+. Neither a compatible legacy
version nor packet-by-packet VPN-only enforcement was established. Interface
activity conditions must not be equated with race-free egress enforcement.

Source: https://www.vallumfirewall.com/

## Separate conditional alternative: local-proxy-only access

If the installed V2Box exposes a suitable local SOCKS/HTTP proxy, a per-app firewall
could potentially allow V2Box/provider external traffic, allow other apps only to
that proxy, and deny their direct external traffic continuously. This avoids
status-based permissive profiles and changing-upstream allowlists.

**Not verified:** whether this V2Box build exposes a suitable proxy, DNS attribution
and remote resolution, UDP/QUIC, app proxy support, and fallback behavior. This is
not transparent whole-Mac VPN support: non-proxy-aware apps may simply remain
blocked. No listener/proxy protocol or live traffic tests were performed.

## Resume checklist — research before implementation

1. Recheck exact release/platform support and shipping capabilities; web pages and
   source branches change. Prefer version-pinned source and vendor documentation.
2. Establish a supported unattended profile-switch interface, necessary privileges,
   authorization, current-profile readback and observable completion/failure.
3. Determine whether restrictive activation blocks existing TCP/UDP flows, including
   already-allowed flows, and obtain evidence rather than infer from UI settings.
4. Identify V2Box's actual provider/helper code identities and bootstrap DNS behavior.
   Do not broadly allow system daemons or every socket merely correlated with V2Box.
5. Define fail-safe behavior for status Unknown, startup, helper/tracker/firewall
   crashes, profile-switch errors and manual override. Keep manual restore usable.
6. Only if feasible, propose a small reversible trial with explicit installation
   and disruptive-test approval, private backups and a demonstrated rollback.
   No deployment, activation, forced VPN crash or reboot is authorized by this note.

The reconnect tracker can remain independent. Do not delay or disable its automatic
reconnect while this firewall research is paused, and do not relabel it leak protection.
