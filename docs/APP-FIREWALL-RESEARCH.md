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

Research resumed against the newest GitHub stable release found at this snapshot,
**LuLu v4.5.5** (GitHub release published 2026-10-30). Its DMG was downloaded to
ignored `.build/` research storage, SHA-256 matched the GitHub API asset digest
`c84c94912405eb852753fc3b51d79ad816d94c6b3b5aec4db4daf2eb8f357597`, and the
read-only disk image passed `codesign --verify --deep --strict` and
`spctl --assess` as **Notarized Developer ID**. The image was detached without
copying, launching or installing the app. Bundle minimum is macOS 10.15, so the
bundle is version-compatible with macOS 13; vendor advises upgrading macOS for
NetworkExtension stability. The vendor product page still advertises v4.5.3,
so release/download pages can lag GitHub.

Source inspection pinned to **v4.5.5** found:

- `LuLu/App/main.m`: command-line handling for installation/upgrade/uninstall/quit,
  not an established public profile-switch command.
- `LuLu/App/StatusBarItem.m`: profile names are exposed in the app's menu, whose
  selection calls into the app's own XPC client. This is a user GUI operation, not
  supported external automation.
- `LuLu/App/XPCDaemonClient.m`, `LuLu/Extension/XPCDaemon.m`,
  `LuLu/Shared/XPCDaemonProto.h`: internal `setProfile` XPC operation. The daemon
  validates the profile path, switches current profile, reloads rules/preferences,
  then replies with success/failure. The UI caller separately shows a success alert
  without checking the Boolean reply. This private XPC method is **not** a supported
  external API or authorization for our tracker to call it. Do not bypass signing/
  peer checks or edit live rule files.
- `LuLu/Extension/FilterDataProvider.m`: outbound new flows get decisions. Switching
  profile loads rules/preferences, but the switch method does not enumerate or
  terminate established sockets; the source inspection found no evidence that
  already-allowed TCP/UDP connections are revoked by a profile change. LuLu docs
  describe subsequent/future decisions. Therefore the requested profile switching
  does not currently meet the user's existing-connection test criterion.
- The restrictive Block Mode is not a strict fail-closed boundary on every path:
  missing/disabled preferences and kernel-origin flows are allowed; an uninspectable
  but still-alive process is explicitly allowed; a different console-user flow is
  allowed; when no GUI alert client is available the `allowNoClient` path creates a
  passive allow rule. Default rules explicitly allow several system processes,
  including `mDNSResponder`. These are intentional product behaviors but need direct
  evaluation before using a restrictive profile; do not assume they only affect the
  V2Box bootstrap flows.
- V2Box UI, provider extension and helper may be distinct process identities. Exact
  installed signed identities and DNS attribution still need inspection. No blanket
  exemption for all Apple programs, shared DNS or system daemons is acceptable by
  assumption.

Sources:
- https://github.com/objective-see/LuLu/releases/tag/v4.5.5
- https://github.com/objective-see/LuLu/tree/v4.5.5/LuLu
- https://github.com/objective-see/LuLu/blob/v4.5.5/LuLu/App/main.m
- https://github.com/objective-see/LuLu/blob/v4.5.5/LuLu/App/StatusBarItem.m
- https://github.com/objective-see/LuLu/blob/v4.5.5/LuLu/Extension/XPCDaemon.m
- https://github.com/objective-see/LuLu/blob/v4.5.5/LuLu/Extension/FilterDataProvider.m
- https://objective-see.org/products/lulu.html

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

### Vallum — strongest next candidate to ask/test, not yet approved

New documentation research found a more relevant feature than profile switching:
Vallum is a per-flow `NEFilterDataProvider` application firewall whose rule
conditions can match whether named system network interfaces are active/inactive.
Its help says a single ruleset can block apps when VPN is not connected; it exposes
app fingerprints, responsible-app identities, and pass/block rules. The official
Vallum 4 help provides a substantive feature description, and release history lists
Vallum 4 releases through 4.1.3 (2023), explicitly adding Sonoma compatibility.
The current 6.0.1 page requires macOS 14.6+, so it cannot be used on the current
macOS 13.7.8 host. Whether a supported/secure Vallum 4 release remains downloadable,
maintained and compatible with this exact Ventura installation needs confirmation.

This is **not yet equivalent to interface-bound routing or a certified kill switch**:
- Help describes conditions on whether interfaces are active, as part of matching
  app flows. It does not say the rule verifies that each app's individual packet
  actually exits through the VPN interface.
- Interface-state conditions can still have transition races or stale state. Need
  vendor confirmation and a controlled test of tunnel-process crash, provider crash,
  `utun` persistence/removal, and immediate physical-interface probes.
- Docs say Vallum passes a flow if no rule matches. Rule order, quick/final-match
  semantics, background action when GUI is absent, unknown condition behavior,
  and all system/Apple/default exemptions must be configured/reviewed. A broad
  `mDNSResponder`/Apple exemption risks authorizing unrelated apps' delegated DNS.
- Vallum documentation describes a Network Extension system filter enabled when
  Vallum.app is started and disabled when it quits. Need prove its login/background
  lifetime, provider failure behavior, installed extension persistence, and safe
  default when the UI/helper is not running.
- There is no independently verified, supported automatic VPN-event integration
  here. However a rule condition tied to `utun` interface presence could potentially
  keep restrictive rules continuously present rather than switch firewall profiles;
  this deserves the next inquiry.
- Vallum 4.0.10 release notes warn that Apple's Packet Filter Provider may cause
  issues in rare circumstances with third-party VPN apps or USB Ethernet adapters;
  it is disabled by default for new installations from that version. Determine if
  this applies to the desired policy and leave this unrelated component off unless
  justified.

Vendor sources:
- https://www.vallumfirewall.com/ (Vallum 6.0.1 currently requires macOS 14.6+)
- https://help.vallumfirewall.com/ (Vallum 4 Help: NEFilterDataProvider, per-flow
  application identity, active/inactive interface conditions, default pass if no
  rule matches)
- https://help.vallumfirewall.com/index.php?chapter=ruleformat
- https://help.vallumfirewall.com/index.php?chapter=rulesets
- https://help.vallumfirewall.com/index.php?chapter=introduction
- https://www.vallumfirewall.com/releasenotes.php (Vallum 4.1.3 Sonoma compatibility;
  4.0.10 Packet Filter Provider warning)

Suggested vendor questions before any purchase/install:
1. Is current Vallum supported on macOS 13.7.8 Intel, and is Vallum 4 still safely
   downloadable/supported? What exact build should be used?
2. Can a deny rule for all third-party apps, conditional on a specific `utunN` being
   inactive, be made persistent and noninteractive, while a V2Box signed-app rule
   permits direct bootstrap/upstream traffic? What happens on a missing/ambiguous
   interface condition?
3. Is the condition based on actual per-flow egress interface, or only system
   interface active state? How quickly does it update on Packet Tunnel crash? Does
   it force-close already established flows or only decide new flows?
4. What are the filter's behavior if its UI, privileged service or Network Extension
   crashes/stops? Does macOS fail open or closed? Does its login item keep filtering
   before the user manually opens the app?
5. Can it enforce without GUI interaction and keep restrictive rules in effect when
   no user is logged in? Which exceptions/default rules apply to delegated DNS?

Do not install it or change its rules before checking compatibility, answers,
rollback and explicit install/live-test approval.

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
