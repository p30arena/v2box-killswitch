# Plan: scoped V2Box-aware VPN firewall

## Purpose and decision

Build only the user's requested outbound policy, if macOS provides a supported,
provable enforcement path. Do not build a generic firewall, clone LuLu, or restore
the PF endpoint allowlist.

> **Firewall Off:** normal networking for all apps.
>
> **Firewall On:** the V2Box app and the exact V2Box tunnel/provider processes may
> connect directly as needed. Every other app may use the network only when its
> flow is actually carried by the VPN. Direct physical-interface egress is denied.
> If path/identity is unknown, deny rather than guess.

V2Box's external endpoint can change without a firewall update. No arbitrary DNS
or all-Apple-app exemptions. Incoming traffic, generic user rules, maps, telemetry,
and unrelated content filtering are out of scope.

This is not permission to activate anything. Current installed PF guard remains
Off; its obsolete IP approval was revoked/preserved privately. The reconnect tracker
remains separate, and is not enforcement. No live firewall, PF, NetworkExtension or
V2Box changes have been made for this plan.

## Why a custom narrow component may be justified

- The user's fault is the VPN application/provider crashing. The enforcement must
  therefore be external to V2Box and remain active while V2Box is absent or down.
- PF can match network-layer attributes and, in limited cases, user/group—not a
  verified signed-app identity. Its app identity is not a rule predicate suitable
  for exempting V2Box without endpoint lists.
- A generic application firewall (LuLu/Vallum) proves app-level filtering, but the
  research so far does not establish an atomic per-flow decision that also proves
  tunnel-vs-physical egress under crash, nor robust existing-flow revocation.
- Keep the enforcement policy to two identities/classes: trusted V2Box/provider,
  and all other flows. Do not recreate the general purpose rule database and UI.

## Proposed macOS enforcement point — feasibility gate, not final architecture

Prototype a macOS `NEFilterDataProvider` system extension configured at
`NEFilterManagerGradeFirewall`:

- `NEFilterFlow.sourceAppAuditToken` provides the source application's audit token
  (macOS 10.15+); `sourceProcessAuditToken` distinguishes the process creating a
  delegated flow on macOS 13+.
- `NEFilterSocketFlow.localEndpoint` and `remoteEndpoint` expose socket endpoints.
  Apple's SDK notes local/remote endpoints can be nil initially and populated later.
  A prototype may test whether the assigned local source address, after route
  resolution, identifies a VPN `utun` address. **This is a hypothesis, not an API
  guarantee that the flow's egress interface is exposed.**
- `NEFilterPacketProvider` callbacks include the actual network interface, but its
  documented packet callback has no source-app audit token. Do not combine these
  APIs with PID/time/tuple guesses and call that atomic app attribution.
- The most important proof is: for every tested non-V2Box flow, does the filter
  receive a reliable, timely signal distinguishing VPN-carried from direct physical
  egress? Unknown or not-yet-populated local endpoints must block, not temporarily
  pass. If this cannot be proved through a supported API, stop: this architecture
  cannot deliver the requested guarantee.

Potential minimal policy predicate, only after evidence:

```text
if FirewallOff: allow
else if trusted V2Box/provider identity: allow direct or tunnel flow
else if supported per-flow evidence proves VPN tunnel path: allow
else: drop
```

Do not substitute `VPN status == Connected`, existence of any `utun`, a source UID,
observed upstream addresses, a polling grace period, or a presumed full-tunnel route
for per-flow evidence. V2Box may itself use several processes; all exemptions require
code-signature/designated-requirement verification and user review. A random helper,
shared resolver or process launched on behalf of an app must not inherit blanket
trust without evidence.

## Existing flow and transition enforcement

Apple's macOS 10.15.4+ `NEFilterDataProvider.updateFlow(_:usingVerdict:forDirection:)`
can change a verdict for an existing `NEFilterSocketFlow`, including dropping it.
This is promising but **does not prove that we can maintain a complete, valid set of
all active flows or learn their actual egress interface**.

If the new-flow proof succeeds, investigate whether the provider can safely retain
and update every non-V2Box flow as tunnel path changes, and what happens when the
provider itself crashes. Explicitly test established TCP, UDP/QUIC, IPv4 and IPv6
flows during abrupt tunnel-interface loss. Do not assume a route event is atomic
with packet delivery. If active-flow revocation has a race that allows direct
fallback, the design remains best-effort and must not be advertised as a strict
kill switch.

## Entitlement, provisioning, install and recovery gate

Before local activation or any later distribution:

1. For the user's requested this-Mac experiment, use local ad-hoc/self-signing
   only. Do not pursue Apple Developer certificates, profiles, or account access.
   This path is specific to this Mac's existing nonstandard security configuration
   and is not transferable or distributable. A separate distribution effort would
   need Apple's signing and entitlement workflow; it is outside this goal.
2. Verify local ad-hoc activation and recovery only on this Mac; never infer support
   on normally protected Macs. LuLu's Apple entitlement is not transferable.
3. Define first-enable consent, filter grade/conflicts with other filters, OS approval,
   failure reporting and a local recovery path. Preserve unrelated enabled filters.
4. Off must have one explicit, authorized path that disables/removes only this
   component's configuration and verifies all apps regain access. No global PF flush,
   no other NetworkExtension configuration removal, and no stored admin passwords.
5. If the entitlement is unavailable, or filter crash semantics cannot satisfy the
   threat model, stop this implementation rather than substitute PF or polling.

Apple SDK evidence inspected on macOS 13.7.8 / Xcode Command Line Tools SDK:

- `NEFilterFlow.h`: app/process audit tokens; socket-flow local/remote endpoints.
- `NEFilterDataProvider.h`: per-flow `handleNewFlow`, `applySettings`, and
  `updateFlow` APIs.
- `NEFilterPacketProvider.h`: interface-bearing packet handler, no app token in
  its public callback parameters.
- `NEFilterManager.h`: firewall-grade filter configuration; up to four enabled
  filters of the same grade on macOS.
- `NEVPNProtocol.h`: `includeAllNetworks`/`enforceRoutes` are VPN-configuration
  properties, not a permission for another app to rewrite V2Box's configuration.

References:
- https://developer.apple.com/documentation/networkextension/nefilterflow
- https://developer.apple.com/documentation/networkextension/nefiltersocketflow
- https://developer.apple.com/documentation/networkextension/nefilterdataprovider/updateflow(_:usingverdict:fordirection:)
- https://developer.apple.com/documentation/networkextension/nefilterpacketprovider
- https://developer.apple.com/documentation/networkextension/nefiltermanager
- https://developer.apple.com/documentation/networkextension

## Execution status (updated 2026-11-01)

The user authorized a read-only observer test on this Mac. No enforcement policy,
PF rules, or V2Box settings were changed.

- Host: Intel macOS 13.7.8 with Command Line Tools only; `xcodebuild` is unavailable.
  The prototype compiles for x86_64 and arm64 with `swiftc` and the installed SDK.
- There are **0 valid code-signing identities** and no local Mac development
  provisioning profiles. This test used an ad-hoc signature with the local-only
  entitlements requested by the user; it is not an Apple Development signature and
  cannot be distributed.
- On this host, `systemextensionsctl developer on` plus approval in System Settings
  allowed the read-only content filter to activate. The host had a pre-existing
  Custom SIP Configuration with Filesystem Protections and Kext Signing disabled;
  this nonstandard state is material to the result. SIP was not changed by this
  work. Developer mode remains on. Do not infer that ad-hoc
  activation will work on a normally protected Mac.
- During the initial connected test, the default route was `utun3`.
  `ifconfig` mapped `240.0.0.2` to `utun3` and `192.168.1.13` to `en0`.
- At `handleNewFlow`, the socket's local endpoint commonly appeared as
  `0.0.0.0`. After requesting a one-byte outbound peek, callbacks sometimes showed
  a concrete local address, including both `240.0.0.2` and `192.168.1.13`; some
  callbacks still had no endpoint, and IPv6 included `::`. An HTTPS request to
  `example.com` returned HTTP 200 while the filter was active.
- The latest test logged the same UUID at `handleNewFlow` and at its outbound
  peek callback, so callback correlation works for the observed flows. Controlled
  HTTPS requests returned HTTP 200 while connected and during an attempted stop
  that reported `Disconnecting`; that is not a confirmed disconnected-state test.
  Paired callbacks showed `240.0.0.2` on `utun3` for some flows and `192.168.1.13`
  on `en0` for others. Several flows still had absent or unspecified endpoints.
- The dedicated probe is positively classified as `test_probe` for both app
  and process audit tokens. With V2Box connected and disconnected, TCP/UDP IPv4/IPv6
  probes exercised the flow callbacks. Some UDP flows resolved to `240.0.0.2`; others
  remained at `0.0.0.0` or `::` and received a probe-only drop verdict. The probe
  reports local socket-call success only; it does not verify packet delivery. The
  attempted VPN stop reported `Disconnecting`, and the route snapshot alone did not
  prove the tunnel had settled disconnected or remained disconnected during probes.
  Seeing `240.0.0.2` in a callback while the default-route snapshot showed `en0`
  therefore does not establish actual egress or falsify endpoint attribution. A
  controlled receiver and confirmed stable tunnel state are still needed.
- The app classifier did not positively identify V2Box or its provider during the
  reconnect capture. Identity-to-route pairing for the target policy remains
  unproven. Do not use this observation path for enforcement. The diagnostic
  observer remains installed for further research. Its V2Box identity-to-route
  pairing remains unproven.
- Read-only signature inspection of `/Applications/V2Box.app` and
  `Contents/PlugIns/PacketTunnel.appex` confirms Apple platform signatures, team
  `5AC5438XDR`, and identifiers `hossin.asaadi.V2Box` and
  `hossin.asaadi.V2Box.PacketTunnel`. These match the classifier allow-list and
  designated requirements. The diagnostic classifier now distinguishes them as
  `v2box_app` and `v2box_provider`. This validates expected bundle signatures, but
  does not show that live filter audit tokens for V2Box flows resolve to them.
  Apple documents `sourceAppAuditToken` as the responsible app token and
  `sourceProcessAuditToken` as the process that created the flow; the latter can
  identify a system process acting for the app. The current logs classify both
  fields as `other`. The macOS 13 SDK marks `NEFilterFlow.sourceAppIdentifier`
  and `sourceAppUniqueIdentifier` unavailable on macOS, so the proposed direct
  identifier cross-check cannot be used by this provider. Continue diagnosis with
  the available audit tokens and inspect their signed-code results without logging
  identifiers. See Apple's
  [source app audit-token docs](https://developer.apple.com/documentation/networkextension/nefilterflow/sourceappaudittoken)
  and [source process audit-token docs](https://developer.apple.com/documentation/networkextension/nefilterflow/sourceprocessaudittoken).
- A changed ad-hoc provider initially failed to restart against the old saved
  filter signature. Removing the filter preference and reinstalling cleanly allowed
  the revised observer to start. The observer requests one outbound byte; if the
  probe endpoint remains wildcard/absent at the first data callback, that probe
  flow now receives an immediate drop verdict. It does not repeat the same
  `passBytes: 0, peekBytes: 1` request, which would inspect the same byte window.
- Historical state at this stage: the observer was installed and active,
  developer mode remained on, and V2Box was connected. The later emergency stop
  and recovery status are recorded at the end of this document.
- Follow-up runtime test after replacing the provider: `systemextensionsctl list`
  showed the extension `[activated enabled]`, and the running provider emitted
  the revised `probe_endpoint_unresolved_drop` events. All four probe scenarios
  reported local socket-call success. TCP4 and TCP6 reached outbound callbacks
  with `240.0.0.2`; UDP4 and UDP6 reached callbacks with `0.0.0.0` and `::`,
  respectively, and were dropped by the provider. This confirms callback
  attribution and verdict issuance for missing endpoints. It does not establish
  whether any packet reached a remote receiver, physical-interface egress, or a
  stable disconnected-VPN path.
- Follow-up with V2Box held disabled at the macOS network-service level: the VPN
  appeared `(Invalid)` and the default route settled on `en0` before probing. The
  probe used numeric destination addresses so it did not depend on VPN DNS. TCP4
  completed its local connect/send calls and its flow endpoint resolved to
  `192.168.1.13`; UDP4 remained `0.0.0.0` and received the unresolved-endpoint
  drop. TCP6 failed locally, while UDP6 was locally accepted and its `::` flow
  received the drop. The service was re-enabled afterward and V2Box returned to
  Connected with `utun3` as the default route. This is a confirmed stable
  disconnected-state callback test, but local socket acceptance and filter logs
  do not prove whether a remote receiver saw a packet.

The route-attribution gate remains **unproven**. Next, verify V2Box code identity
classification, then repeat controlled flow tests across IPv4/IPv6 and TCP/UDP,
including missing endpoints, confirmed path transitions, controlled receiver
acknowledgment, and provider failure. Do
not implement enforcement until each flow's signed app identity and route evidence
are reliable and existing-flow/crash behavior passes. The user chose local
ad-hoc signing; Apple Development signing and provisioning profiles are out of
scope for this experiment.

### Review fixes following the live observations

The classifier now checks dynamic code validity and an Apple-anchored requirement,
requires the observed V2Box team, and accepts only the two inspected identifiers:
`hossin.asaadi.V2Box` and `hossin.asaadi.V2Box.PacketTunnel`. Other identifiers
under that prefix receive no V2Box label. These labels remain diagnostic only.
UUID tracking expires entries after five minutes, evicts the oldest entry at a
4096-entry limit, and clears state when the provider stops.

The CLI build produces `FlowProbe`, a diagnostic binary with signing ID
`org.v2boxkillswitch.firewallprobe.testprobe`. It performs raw TCP/UDP socket
operations to `example.com:443` for IPv4 and IPv6. A successful `connect`, `send`,
or `sendto` proves only local socket-call acceptance; it does not prove remote
delivery or response. `--host hostname-or-IP` selects a target; IP literals avoid
DNS dependency during a disconnected-path test. TCP connect uses a three-second
timeout. The observer labels that exact identity `test_probe`,
separately for the responsible app and creating process. This ad-hoc identity is
for test attribution only and grants no firewall exemption. Probe logs and paired
flow callbacks positively verified this identity on the live observer. A controlled
receiver with an acknowledgment is still required to prove delivery or non-delivery.

The probe rejects unknown arguments and a missing `--host` value before running a
scenario. Hostname resolution and TCP connect each have a three-second deadline;
TCP sockets set `SO_NOSIGPIPE` so a peer close is reported as a send failure rather
than terminating the process. The current universal build passed signature checks,
the invalid-argument path exited with status 2, and all four connected-path probe
scenarios completed with positive local socket-call results. Live observer logs
matched the probe identity for all four scenarios. `FlowProbe --peer-close-check`
also passed against a loopback listener configured to reset its accepted connection;
the subsequent send returned an error and the process exited normally. DNS timeout
handling passed a forced 1 ms deadline check: the resolver child was terminated and
the probe returned normally. A real system resolver stall was not induced. A
nonexistent `.invalid` hostname returned a normal local lookup failure. The
`--tcp-echo-check` mode sends a newline-terminated marker to `tcpbin.com:4242`
and requires the exact bytes back. It once received an IPv4 echo, but subsequent
runs timed out waiting for IPv4 echo and failed to connect over IPv6. A separate
`nc -6` connection check succeeded, so the IPv6 application-level echo remains
unverified. Treat this public service as exploratory only, not a reliable test gate.
`FlowProbe --loopback-ack-check` exchanged a byte with a local TCP echo listener
and verified the echoed acknowledgment. Its accept and response waits are bounded
to two seconds. This verifies the probe's acknowledgment path over loopback only;
it does not establish remote delivery or VPN egress.
`FlowProbe --https-echo-check` POSTed a unique marker to the public
`testserver.host/echo` endpoint and verified the HTTP response contained that
marker. The live observer classified both app and process as `test_probe`; the
outbound callback reported `240.0.0.2` while V2Box was connected. This confirms
remote application-level delivery and response for this request, but the endpoint
is a public test service and the local endpoint address alone does not independently
prove the physical egress interface.
An attempt with the V2BOX network service disabled and the default route on `en0`
did not receive an HTTP acknowledgment. The paired observer logs show the
`test_probe` app flow remained at `0.0.0.0` and received
`probe_endpoint_unresolved_drop`. A separate IPv4 `curl --resolve` control request
to the same endpoint returned HTTP 200 while V2BOX was disabled and `en0` was the
default route, confirming that the endpoint was reachable over that path. The
service was re-enabled afterward and V2Box returned to Connected. This confirms
the observer issued its intended drop verdict for the unresolved probe flow; it
does not independently verify packet non-delivery at the remote service.

The probe was subsequently hardened to retain every DNS address returned for the
requested address family, enforce one monotonic three-second deadline across TCP
echo readiness and partial reads, and retry interrupted `poll()` calls without
resetting deadlines. Its UDP failure result now distinguishes failed `sendto()`
from failed TCP connect. The universal ad-hoc build, Swift type-check, resolver
deadline, loopback acknowledgment, and peer-close diagnostics passed after these
changes; no observer reinstall was needed.

### Per-flow route attribution API review

The `NEFilterDataProvider` path used by this prototype exposes local/remote
endpoints, socket family, type, and protocol, but no per-flow interface index or
selected route. Apple documents that `localEndpoint` can be nil when
`handleNewFlow` runs and is populated after data arrives. The newer
`localFlowEndpoint` is still an `NWEndpoint`, not an interface/path identifier.
See [NEFilterSocketFlow](https://developer.apple.com/documentation/networkextension/nefiltersocketflow)
and [localEndpoint](https://developer.apple.com/documentation/networkextension/nefiltersocketflow/localendpoint).

There is a promising supported route signal in the separate macOS
`NEFilterPacketProvider` API: its packet handler receives the ingress/egress
`NWInterface` and direction for each packet, and `NWInterface` exposes the name
and index. Apple supports packet content filters on macOS and permits a
configuration to enable packet and socket filtering. See [NEFilterPacketHandler](https://developer.apple.com/documentation/networkextension/nefilterpackethandler),
[NWInterface](https://developer.apple.com/documentation/network/nwinterface),
and [content filter providers](https://developer.apple.com/documentation/networkextension/content-filter-providers).

That packet callback does not expose the app/process audit tokens or a documented
flow UUID. The installed macOS 13 SDK declares `NEFilterPacketContext` as an empty
class, so tying its interface observation to the app identity from the existing
data provider appears to require correlating packet headers with socket endpoints.
That join may race or be ambiguous when endpoints are unresolved or tuples are
reused. The live data-provider observations still show unspecified addresses.
Therefore the route API gap has a plausible workaround, but the critical identity
to packet/interface correlation is unproven. Phase 1 remains open and enforcement
must not begin until a read-only packet-provider experiment demonstrates complete,
race-free correlation for controlled TCP/UDP IPv4/IPv6 flows and tunnel transitions.

The prototype now includes `ReadOnlyPacketObserver`, which samples only interface
name/index, direction, packet length, and time at a one-second per-interface/
direction rate, then allows every packet. A same-bundle dual-provider build loaded
the packet callback and showed `utun3` (index 19) and `en0` (index 8), but macOS
reported no active data-provider registration for that bundle. The subsequent
HTTPS request was acknowledged, but no identity callback was available in that
configuration. The package was then split into distinct data and packet system
extensions, with separate bundle IDs and Mach service app groups. macOS activated
both extensions, but enabling both in one filter configuration caused the filter
session to exit. No packet-interface callback was observed from the separate
packet extension during the attempted combined test.

The host is now restored to the previously working flow-only configuration:
`filterSockets=true`, `filterPackets=false`, and no packet-provider bundle ID.
Both system extensions remain installed and activated; the packet extension is
not enabled in the active filter configuration. V2Box is Connected, and a new
HTTPS echo probe succeeded with both app and process positively identified as
`test_probe`; its flow moved from an absent local endpoint to `240.0.0.2`.
The route-to-identity join remains unproven. No cleanup or reboot was performed.

### Follow-up local verification (2026-11-01)

After rebuilding the current sources, status checks still showed the data
extension activated, the packet extension installed but not selected, the filter
enabled with socket filtering only, and V2Box Connected with `utun3` as default
route. A new HTTPS echo attempt failed to obtain a verified response; its matching
flow was classified as `test_probe`, and its outbound callback reported
`240.0.0.2`. A separate TCP connect/send probe to `1.1.1.1:443` completed its
local socket calls and produced paired `test_probe` callbacks with the same flow
UUID, changing from `0.0.0.0` at new-flow time to `240.0.0.2` at the outbound
callback. This verifies live callback identity and endpoint observation for that
flow, but not remote delivery or the actual egress interface. No filter settings,
installation, VPN state, or cleanup were changed during this check.

A follow-up four-scenario run against `example.com:443` while V2Box remained
connected produced these results: TCP4 completed local connect/send calls and its
outbound callback changed from `0.0.0.0` to `240.0.0.2`; TCP6 failed its local
connect and showed `::` only at new-flow time; UDP4 and UDP6 completed local
`sendto()` calls, then their outbound callbacks remained at `0.0.0.0` and `::` and
logged `probe_endpoint_unresolved_drop`. The process exited nonzero because TCP6
failed. The UDP results show the provider issued drops after local send acceptance;
they do not prove remote non-delivery. No route/interface or remote receiver
measurement was made.

An attempted disconnected-state follow-up ran `scutil --nc stop V2BOX`, which
returned success, but status remained Connected and the default route stayed on
`utun3` for the full 30-second observation window. The service status showed
repeated connect/disconnect counts, while its configuration reported
`OnDemandEnabled: FALSE` and retained Connect rules. The reason the stop did not
produce a stable disconnected interval was later explained by the running,
unpaused `org.v2boxkillswitch.reconnecttracker` LaunchAgent. No probes were run
during that first attempt.

For a controlled follow-up, the tracker's persisted Pause preference was enabled
and its LaunchAgent restarted; the tracker ran paused. `scutil --nc stop V2BOX`
then reached Disconnected with `en0` as the default route. With V2Box disconnected,
TCP4 completed local connect/send calls and its paired flow callback changed from
`0.0.0.0` to the physical address `192.168.1.13`. UDP4's callback remained at
`0.0.0.0` and received `probe_endpoint_unresolved_drop`. TCP6 connect failed and
showed `::` only at new-flow time; UDP6's callback remained at `::` and received
the unresolved-endpoint drop. Both UDP probes reported local `sendto()` acceptance
before their filter verdict; this does not prove remote delivery or non-delivery.
The test process exited nonzero because TCP6 could not connect. V2Box was started
again and reached Connected with default route `utun3`; the tracker Pause
preference was cleared and the LaunchAgent restarted. Final status confirmed the
tracker running with Pause off, the observer enabled in socket-only mode, and V2Box
Connected. The installed observer and its filter configuration were not changed.

The data-provider bundle was then rebuilt with the IPv4-mapped IPv6 unspecified
address check, incremented to version 5, ad-hoc signed with local entitlements, and
activated on this same Mac. `systemextensionsctl` reports version `0.1/5`; filter
status remains enabled with sockets on and packets off. A post-activation TCP4
probe to `1.1.1.1:443` completed local connect/send, but its matching provider log
showed only the new-flow callback during the inspected interval, so this run does
not verify the revised mapped-address guard or a resolved outbound endpoint. The
version 5 test also used the newly built per-request UUID HTTPS marker, but no
verified HTTP echo was obtained. This remains a locally ad-hoc experiment on the
development Mac, not a normally protected isolated test system or a valid
Apple Development provisioning setup.

### Audit-token identity follow-up (2026-11-01)

The observer's prior `SecCodeCheckValidity` call reported
`unknown_dynamic_validity` for some live guest-code audit tokens. Apple documents
that call as dynamic validation, distinct from static signature validation. The
classifier now reads the signing identifier and team entitlement through
`SecTaskCreateWithAuditToken`, then checks the reviewed V2Box identifiers against
an Apple-anchored static code requirement. It logs only coarse identity classes,
not raw identifiers. The universal ad-hoc build verified, and the data provider
was activated as version `0.1/7` in the existing flow-only configuration.

During live V2Box reconnect, multiple flows were positively classified as
`v2box_provider` for both source app and source process; a matching outbound flow
reported `192.168.1.13` while the VPN was Connected and the default route was
`utun3`. Other flows remained `other_no_team_identifier` or
`unknown_signing_identifier`. This is new evidence that the provider identity can
be recovered for some flows, but it does not establish complete classification,
identify the V2Box GUI app, or prove the actual packet interface for each flow.
The reconnect tracker was resumed and V2Box remained Connected after the capture.

### Command-line build and local observer run (2026-11-01)

`bash menu-bar/FilterPrototype/build-read-only-prototype.sh` successfully compiles
the data provider, packet provider, extension entry points, and host app against the
installed macOS 13 SDK using `swiftc` for both x86_64 and arm64. It combines
universal binaries with `lipo`, assembles a host `.app` with two nested
`.systemextension` bundles, and ad-hoc signs/verifies them with `codesign`. The observer first saw
`0.0.0.0` at new-flow time; an experimental one-byte outbound peek then exposed
some concrete local source addresses. It did not log destinations, hostnames,
ports, or payload bytes. No Xcode app or `xcodebuild` was used.

The default ad-hoc package intentionally omits restricted entitlements and embedded
profiles, so macOS cannot activate it. For a local development-signed package, the
script accepts `SIGNING_IDENTITY` (Apple Development), `TEAM_ID`,
`TARGET_DEVICE_UDID`, `APP_PROFILE`, `EXTENSION_PROFILE`, and
`PACKET_EXTENSION_PROFILE`; the profiles must match the host, data-provider,
and packet-provider bundle IDs and authorize the required entitlements. Before
signing, [`validate-profiles.py`](../menu-bar/FilterPrototype/validate-profiles.py)
decodes the profiles with Apple's `security cms` and checks their team, App IDs,
test-device registration, macOS platform, expiry, development status, Network
Extension capability, and the host's system-extension-install entitlement.
The host's explicit `--activate-observer` path requests system-extension activation
and enables its diagnostic filter configuration; `--disable-observer` turns that
filter configuration off, and `--remove-observer` removes the preference. These
commands were exercised on this Mac. The enabled filter received live flows, but
the local-address route correlation remains unqualified as described above. The
latest provider source has since been rebuilt and activated; its unresolved-probe
drop behavior was exercised live as recorded above. The observer remains installed.

### Optional Apple Developer signing notes (out of scope for the local experiment)

The following was researched as an alternative signing route. The user chose
ad-hoc/self-signing on this Mac, so do not pursue these account steps for the
current goal.

1. In the Apple Developer account, register the host, data-provider, and
   packet-provider App IDs used in the bundle metadata. Enable Network Extensions
   for both provider IDs and System Extension for the host app ID.
2. Create an Apple Development certificate using a CSR generated in Keychain Access
   on the build Mac. Install the issued certificate into that Mac's login keychain;
   keep the private key there.
3. Register the disposable test Mac and note its provisioning UDID. For example,
   on that Mac run:

   ```sh
   system_profiler SPHardwareDataType -json | python3 -c 'import json,sys; print(json.load(sys.stdin)["SPHardwareDataType"][0]["provisioning_UDID"])'
   ```

4. Create Mac App Development profiles for the host, data-provider, and
   packet-provider App IDs. Include the Apple Development certificate and test Mac
   in all three, then download them. The local validator checks the target UDID,
identifiers and allowed entitlements before signing. The packet provider uses a
separate app group for its Mach service and needs a matching packet-extension
profile.

Apple's Developer Technical Support guidance distinguishes these development
profiles from Developer ID distribution profiles: development uses the standard
`content-filter-provider` entitlement, while direct Developer ID distribution uses
`content-filter-provider-systemextension`. A paid developer team can create
development profiles for restricted entitlements without the separate distribution
approval process. See [Apple DTS on entitlement prototyping](https://developer.apple.com/forums/thread/735356)
and [Apple DTS on Network Extension signing](https://developer.apple.com/forums/thread/737894).

Apple's documented package layout uses a host app with the provider in
`Contents/Library/SystemExtensions/`; its provider Info.plist maps
`com.apple.networkextension.filter-data` to the principal class, and the host
activates it through `OSSystemExtensionRequest`. Apple's sample code and current
deployment documentation provide these packaging/activation references:
[Filtering Network Traffic](https://developer.apple.com/documentation/networkextension/filtering-network-traffic),
[Network Extension provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment),
and [system extensions](https://developer.apple.com/documentation/systemextensions).
Apple DTS recommends Apple Development signing and standard Network Extension
entitlements during development; Developer ID-specific entitlements are needed for
direct distribution. Manual signing means Xcode is not a build dependency, but the
Apple Developer account, enabled App ID capabilities, registered test Mac, identity,
and profiles are still required.
Apple's system-extension developer mode can relax the requirement that the host
app live in `/Applications`, but Apple still requires the proper code signature and
entitlements for normal activation. It was enabled temporarily for the local
observer experiment and remains on. The current host's pre-existing custom SIP
state affected this ad-hoc result; do not treat it as a general activation
workaround. Further development on a normally protected Mac still needs a
team-authorized signature/profile and approval.

Apple reference: https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension

## Phased implementation and stop conditions

### Phase 0 — verify local self-sign and recovery controls

- Build with `ADHOC_ENTITLEMENTS=1` using Command Line Tools, then verify the host
  and provider signatures and embedded entitlements.
- Confirm the menu-bar controls can disable the saved filter and request extension
  termination. Verify ordinary connectivity after any runtime test.
- Keep the current test limited to this Mac's existing developer/SIP configuration;
  do not claim the same ad-hoc activation works on another Mac.

### Phase 1 — read-only flow-observation prototype

Create a disposable, non-enforcing test extension or test harness that records only
synthetic test labels and these per-flow facts: app identity present/absent, process
identity present/absent, local endpoint present/absent, local address family, observed
source address, path/interface correlation result and timestamps. No destinations,
DNS names, content, public IP probe, production user traffic logging or firewall
changes. Use controlled test applications and a local receiver.

Test each flow with VPN disconnected/connecting/connected/disconnecting and with
IPv4/IPv6. Establish whether local endpoint maps reliably to the actual tunnel vs
physical route for TCP, UDP and delegated/system flows; include unknown results.

**Gate:** if app identity and actual route cannot be determined for each flow without
race/guess, stop. Publish no enforcement claim.

### Phase 2 — isolated verdict prototype

Only after Phase 0/1 succeed, construct minimal fixed policy, no generic rule editor:

- `Off` permits all flows; verify explicit off can always be invoked and read back.
- `On` exempts only verified V2Box app/provider code identities.
- Every other flow is allowed only with affirmative per-flow tunnel-path evidence;
  unknown/malformed/stale identity or path is dropped.
- Restrict existing flows on path loss using `updateFlow` if completeness/lifecycle
  can be demonstrated. Do not rely on status polling for the security decision.
- Separate atomic durable user intent from observed active enforcement; report `On`
  only after filter installation/readback succeeds. A failure must not misreport
  protected status.

Run in a disposable macOS VM or separate test host if the relevant provider and
Apple entitlement can be exercised. Build local leak receivers (IPv4/IPv6, TCP/UDP)
on physical and test-tunnel paths. Verify zero physical-interface payloads from
non-V2Box processes after forced tunnel loss, including established flows; verify
V2Box upstream changes and DNS still reconnect. Test filter extension crash/stop,
app logout, sleep/wake, network switch, reboot, recovery and explicit Off. Every test
must distinguish packet counters/captures from application success; no phone-home
IP-check-only proof.

### Phase 3 — review and approval before personal-machine trial

Before any user-machine install or disruptive test, deliver exact binaries, entitlement
state, allow identity manifest, undo procedure, independent test evidence, known
limitations and ordinary-user recovery route. Obtain separate explicit approval.
The current project withdrawal and PF incident remain relevant; no automatic
re-enable after reboot or crash without separately reviewed opt-in semantics.

## Success criteria

All of the following are mandatory before calling it a kill switch:

1. Firewall Off restores ordinary access without changing another firewall/filter.
2. With it On, V2Box/provider can resolve/bootstrap/connect to changing peers while
   the tunnel is down, without fixed address/port/protocol exceptions.
3. Every non-V2Box app's tested IPv4 and IPv6 egress is tunnel-only; on tunnel loss,
   no packet from those apps escapes via physical interfaces, including established
   flows and abrupt provider/app crash.
4. Unknown identity, missing endpoint/path data, filter/helper failure and stale
   evidence fail closed for non-V2Box traffic and visibly report enforcement failure.
5. Firewall remains active independently of V2Box process/provider lifetime, but
   deliberate Disable remains reliable and restores access.
6. The local ad-hoc signature and installation are verified on this Mac, and an
   explicit Disable restores ordinary connectivity.

A callback that arrives quickly, a Connected indicator, unit tests, route-table
snapshots, simulations, successful reconnect, or a clean compile is not sufficient.
If strict no-leak behavior cannot be established, document it as a best-effort
tracker/firewall and do not claim kill-switch protection.

## Local signing, activation and recovery status (2026-11-01)

- `security find-identity -v -p codesigning` reports **0 Apple-issued signing
  identities**, and there are no local provisioning profiles. This is expected
  for the user's chosen ad-hoc signing path, not a blocker.
- The built local app is ad-hoc signed (`Signature=adhoc`, no TeamIdentifier).
  Its successful `codesign --verify` result verifies the local ad-hoc signature.
- The host's `--status` command reports `enabled=true`, sockets true, packets false,
  data provider `org.v2boxkillswitch.firewallprobe.extension`, and no packet
  provider. `systemextensionsctl list` reports version `0.1/8` as
  `[activated enabled]`; older flow/packet versions remain marked `terminated
  waiting to uninstall on reboot`.
- V2Box is Connected, the default route is `utun3`, and HTTPS to `example.com`
  returned HTTP 200 after activation. A normal DNS request briefly timed out earlier
  in the session; a numeric-IP HTTPS request succeeded during that period. No
  filter setting or VPN state was changed in response to that transient result.
- This is a MacBookPro13,3 running macOS 13.7.8. The user explicitly wants the
  test on this Mac; it is not isolated from their normal connectivity. The menu-bar
  recovery app is running alongside the flow-only observer.
- The menu offers Enable observer, Disable filter, and a one-click emergency path
  that attempts to disable and remove this filter preference before requesting
  deactivation of both extension identifiers. It reports when System Settings
  approval is needed and labels an enabled saved preference as runtime-unverified.
  The revised host was rebuilt and relaunched; the emergency action has not been
  exercised, to preserve the active installation and avoid another reinstall.
- The shared disable/enable manager code was exercised through the host CLI:
  Disable saved `enabled=false` while HTTPS still returned HTTP 200; activation
  restored `enabled=true` and reused the existing `[activated enabled]` version
  `0.1/8` without an uninstall/reinstall cycle. The actual menu item click was not
  automated because macOS denied AppleScript assistive access; the complete
  emergency path (which removes preferences and requests deactivation) remains
  untested.
- The reconnect tracker was confirmed running but persisted as paused (`paused=1`),
  contrary to the expected active state. It was resumed (`paused=0`) and kickstarted;
  launchd then reported it running at 10 launches. V2Box remained Connected and
  HTTPS returned HTTP 200. No VPN disconnect test was performed.

Connected-path probe evidence after activating version `0.1/8`:

- `FlowProbe --https-echo-check` received the unique HTTP echo response. This proves
  remote application-level delivery and response while V2Box was Connected, but
  not the egress interface by itself.
- IPv4 TCP to numeric `1.1.1.1:443` was locally accepted. `FlowProbe`'s
  `getsockname()` and the paired observer callback both reported `240.0.0.2`, which
  `ifconfig` maps to `utun3`. Local socket acceptance is not remote delivery proof.
- Unconnected IPv4 UDP to the same numeric target was locally accepted by `sendto`,
  while `getsockname()` and the observer callback both remained `0.0.0.0`. The
  observer dropped this synthetic probe because its local endpoint was unresolved.
  This proves the narrow probe rule fired, not that a remote receiver saw no packet.
- Connected IPv4 UDP to the same target was locally accepted; both
  `getsockname()` and the observer callback reported `240.0.0.2` (`utun3`). This
  shows local-address inference can work for connected UDP sockets. It does not
  generalize to unconnected UDP.
- A 20-minute live-log sample repeatedly classified V2Box provider flows as
  `v2box_provider`; it did not produce a `v2box_app` classification. The GUI
  application's own identity therefore remains unverified in this run.
- The first IPv6 attempt incorrectly paired AF_INET6 sockets with the IPv4 literal
  `1.1.1.1`; those `resolution_failed` results were invalid as IPv6 route evidence.
  Corrected tests used `2606:4700:4700::1111`: TCP6 returned `connect_failed`,
  unconnected UDP6 was locally accepted but both `getsockname()` and the observer
  returned `::`, and the observer dropped that synthetic probe. Connected UDP6
  returned `connect_failed` before sending. Thus no IPv6 egress path was verified;
  unconnected UDP6 had only wildcard evidence. `ifconfig` maps `192.168.1.13` to
  `en0`; live V2Box provider flow callbacks reported that source address, consistent
  with the provider's physical upstream socket. No packet capture tied those flow
  callbacks to actual egress.

## Feasibility decision: no-go for strict enforcement on this API path

The route-attribution gate fails the required universal coverage criterion on
macOS 13.7.8: `NEFilterSocketFlow` exposes no egress-interface property,
unconnected UDP4 and UDP6 remain wildcard even after the data callback, and IPv6
TCP/connected UDP did not establish a path here. The address-to-interface mapping
is useful evidence for specific resolved flows only. Apple's packet callback
reports an interface but does not include the source application's audit token;
the packet context exposes no public flow identifier to join with the data-flow
callback. See Apple's [`NEFilterPacketHandler`](https://developer.apple.com/documentation/networkextension/nefilterpackethandler)
and [`NEFilterPacketContext`](https://developer.apple.com/documentation/networkextension/nefilterpacketcontext)
documentation. A PID/time/tuple join would be a heuristic, not reliable per-flow
proof, so this implementation must not proceed to enforcement. The current
diagnostic provider allows ordinary flows and drops only unresolved synthetic
probe flows; it does not block unknown user traffic. A materially different,
supported interface would need to close these gaps before this gate is reopened.

The latest full Command Line Tools build produced x86_64/arm64 ad-hoc-signed
artifacts that passed signature verification. The new connected-UDP probe mode
reported the local source address without logging remote endpoints or ports; its
unknown-option guard also returned the expected status 2.

## Observer uninstall (2026-11-01)

At the user's request, the observer was uninstalled while preserving all source:

- `--remove-observer` removed the saved Network Extension filter preference.
- `systemextensionsctl uninstall -` succeeded for both
  `org.v2boxkillswitch.firewallprobe.extension` and
  `org.v2boxkillswitch.firewallprobe.packet`.
- The filter manager now reports `enabled=false`, sockets/packets false, and both
  provider IDs nil. `systemextensionsctl list` shows no active observer; its old
  versions, including `0.1/8`, are `terminated waiting to uninstall on reboot`.
- The observer menu-bar process was stopped and its generated
  `.build/filter-prototype-self-signed` directory removed. The source under
  `menu-bar/FilterPrototype/` remains in the repository.
- The V2Box reconnect tracker was left running/unpaused, V2Box remained Connected,
  and HTTPS returned HTTP 200 after removal. A reboot is still needed for macOS to
  purge the pending extension records; no reboot was performed.

Apple Developer certificate/profile requirements apply to other signing and
distribution paths, which the user rejected. They are not prerequisites for this
locally self-signed experiment. The observer is uninstalled and its filter
preference is removed. Old extension uninstall records remain pending reboot.
The per-flow route-attribution gate remains unproven, and enforcement remains out
of scope until it passes.
