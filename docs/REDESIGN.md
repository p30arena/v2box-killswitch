# Replacement status — experimental, uninstalled development kit

The original release remains withdrawn. Do not install legacy scripts or plists.
The replacement now has executable Enable/Disable/Refresh paths. An Off-state
helper installation has been staged locally for IPC tests; no approved policy or
PF activation was performed. It is not release-ready or a verified kill switch.

## Components

- `src/policy.py`: deterministic, interface-scoped IPv4/IPv6 rules; explicit TCP/UDP
  peers, optional LAN subnets, exact router exceptions and quarantine generation.
- `src/gateways.py`: read-only scoped IPv4 router discovery across physical ports.
- `src/endpoints.py`: approved profile inventory with explicit IPs/revisions/expiry.
- `src/coordinator.py`: revoke stale tunnel/peer grants on approval/discovery errors.
- `src/controller.py`: durable disable intent and serialization with refresh.
- `src/pf_driver.py`: scoped PF operations, canonical read-back, owned enable token.
- `src/token_store.py`: boot-bound atomic token journal; unknown token outcomes
  require reconciliation rather than silently acquiring more enable references.
- `src/runtime.py`: root-only executable entrypoint with fixed trusted paths;
  discovery, preflight, Enable/Disable/Refresh and status capability checks.
- `src/recovery.py`, `src/vpn_commands.py`, `src/health.py`: tested recovery/health
  components, not integrated into an installed user-session recovery agent.
- Native menu-bar client/helper: mutual exact-build XPC pinning, management
  authorization for protection changes, serialized timer refresh and fixed backend
  calls. Reconnect is still refused pending authenticated user-session integration.
- Development-kit builder: local ad-hoc signing, mutually pinned artifacts,
  root-backend zipapp and explicit management-right provisioning utility. Build
  scripts never install, register or launch any of these components.

## Actual safety gates

Enable requires reviewed root-owned configuration, a current approved peer set,
unique current tunnel descriptor when connected, physical-router discovery, a
first quick root anchor, no preexisting PF states, no skip interfaces, no legacy
root refresher, successful syntax validation and complete canonical rule read-back.
Failed updates request quarantine; explicit Disable persists before anchor removal.
No global flush or `pfctl -d` is used by the new backend.

The root anchor syntax was checked non-activating on this Mac:
`anchor "com.p30arena.v2box-killswitch" quick` canonicalizes to
`anchor "com.p30arena.v2box-killswitch" quick all`. Previous fake fixtures had an
incorrect ordering; the driver now recognizes the observed syntax.

## Endpoint changes — unsolved trust/bootstrap constraint

A preapproved set supports rotation within it. Arbitrary new server addresses
require local approval or a separately authenticated bootstrap/update channel.
No such channel or endpoint approval UI is provided yet. No general DNS exception
is introduced. Unknown/expired profiles quarantine, not transparently reconnect.
Automatic profile detection from V2Box is also not integrated: the selected profile
in the reviewed config is authoritative.

## Release blockers

- Only Off-state helper provisioning has been performed. Administrator-authorization
  verification, activation and packet captures are still pending for the replacement.
- No authenticated user-session reconnect agent integration; the menu reconnect
  operation deliberately reports unavailable.
- Same-boot PF reset/token reconciliation is incomplete. A different-boot journal
  is rejected rather than reused. Boot-time gap/protection is NOT proven.
- Timeout/crash recovery across helper/backend and emergency action when the
  helper is unavailable still need independent validation.
- IPv6 router discovery, full DHCP renewal coverage, tunnel identity guarantees,
  interface-name reuse and interaction with unrelated PF/security software need
  review and testing. Descriptor matching is not cryptographic provider identity.
- Ad-hoc local signing is not notarized public distribution. Explicit repinning
  is required after updates; there is no reviewed updater/uninstaller yet.

Router access is intentional direct-network permission: ICMP echo, TCP 80/443
and DHCP renewal only. It excludes general router DNS and the rest of the LAN.
Router web/proxy services on the allowed ports remain an intentional bypass;
PF cannot restrict those exceptions to an admin browser.

## Non-activating checks/build

```sh
python3 -m unittest discover -s tests -v
bash menu-bar/test-security.sh
bash menu-bar/test-ipc.sh
python3 tools/build_development_kit.py
```

The IPC check runs only an unprivileged anonymous test listener, never the root
helper or a registered service. All output is confined to temporary files or
ignored `.build` directories. Building
the development kit does local ad-hoc signing only; it does not install services,
change authorization rights, load PF or launch any app/helper/backend.
