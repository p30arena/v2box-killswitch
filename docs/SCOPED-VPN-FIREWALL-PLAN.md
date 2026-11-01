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

Before writing the real extension:

1. Confirm with the active Apple Developer team and current Apple documentation
   which NetworkExtension entitlement(s), system-extension entitlement, distribution
   provisioning profile, Developer ID signing and notarization are needed for a
   macOS content-filter provider. LuLu's Apple entitlement is not transferable.
2. Confirm the exact capabilities are available to this team/product identifier;
   do not assume development signing or ad-hoc binaries can activate the filter.
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

## Phased implementation and stop conditions

### Phase 0 — prove Apple capability (no code deployment)

- Obtain written entitlement/provisioning requirements for macOS firewall-grade
  content filtering from Apple Developer support/portal.
- Confirm a development app/system extension can be signed with the needed entitlement.
- Stop if entitlement is unavailable; do not spend time implementing an unshippable
  filter.

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
6. Apple entitlement/signature/installation are supported for the actual release path.

A callback that arrives quickly, a Connected indicator, unit tests, route-table
snapshots, simulations, successful reconnect, or a clean compile is not sufficient.
If strict no-leak behavior cannot be established, document it as a best-effort
tracker/firewall and do not claim kill-switch protection.
