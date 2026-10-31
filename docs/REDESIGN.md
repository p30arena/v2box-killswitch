# Replacement status — development only

No operational replacement is available. Do not install legacy scripts or plists.
The README withdrawal warning remains in effect.

## Implemented and offline-tested

- `src/policy.py`: deterministic, interface-scoped outbound policy compiler;
  explicit numeric endpoint set, TCP/UDP and IPv6; explicit optional LAN subnets;
  exact gateway exceptions. No system operations.
- `src/gateways.py`: read-only scoped IPv4 gateway discovery; on-link validation;
  detects an observed route change during the snapshot. No DNS or PF operations.
- `src/endpoints.py`: explicit profile inventories with revisions and expiry;
  new profile replaces old endpoint set rather than accumulating permissions.
  Unknown or expired endpoints require approval. No automatic DNS bootstrap.
- `src/controller.py`: durable enabled/disabled intent, interprocess lock,
  serialized refresh/disable, read-back status through an injected backend.
  Tests use a fake PF backend only. No operational PF backend is supplied.
- `src/pf_driver.py`: experimental injected-runner PF driver tested only against
  a fake kernel. Scoped stdin anchor replacement/removal, first quick-root-gate
  check and explicit owned-token acquisition/release. No default command runner,
  daemon or executable entrypoint is supplied.
- `src/token_store.py`: boot-bound, atomic token journal using directory-relative
  file operations, ownership/mode validation and symlink/hardlink rejection.
  Tested in temporary directories; not installed as privileged state.
- `menu-bar/`: native Swift/AppKit preview and an unprivileged XPC client shell.
  Preview controls are simulated; client reports ERROR/UNKNOWN and disables actions
  with no helper. Neither is connected to operational PF controls.

## Endpoint changes: important unresolved constraint

It is impossible to infer an arbitrary new server address from nothing while all
traffic needed to retrieve that address is denied. Unrestricted DNS, HTTPS or
process-socket discovery is not an acceptable substitute for explicit trust.
Preapproved addresses allow rotation within that set. Changes outside that set
need local approval or a separately authenticated, narrowly permitted bootstrap
channel. This implementation supplies neither a trusted update channel nor an
approval UI yet. It does not claim fully automatic recovery for arbitrary remote
configuration changes.

## Deployment blockers

1. Authenticated privileged helper + signed native UI integration (see
   `XPC-HELPER.md`). Only the client shell exists. Validate authorization and
   signing on each supported macOS release. No arbitrary shell input.
2. Finish and validate the experimental PF driver: durable root-owned token
   storage integration, same-boot token reconciliation, complete ruleset read-back, skip/state
   interaction, preexisting states, and real macOS output/atomicity. Fake-kernel
   tests cannot prove these. Do not supply an operational runner before review.
3. Crash-consistent kernel-state/intent reconciliation and an independent local
   emergency action that works if helper/IPC dies. Mock tests do not prove this.
4. Actual network-change monitoring and removal of stale tunnel/gateway passes.
   Interface name reuse must not grant traffic to another VPN's tunnel.
5. Endpoint approval UI and trusted update design; explicit errors instead of
   appearing healthy when approval or bootstrap is unavailable.
6. IPv6 gateway discovery and real DHCP renewal/ND tests. The draft compiler's
   bootstrap rules do not yet cover every renewal or network topology.
7. Packet captures on supported macOS versions, with health tests, endpoint
   changes, profile switching, sleep/wake, watchdog failures, and boot timing.
   Never claim protection across boot before measurement.

Router access is a deliberate bypass: allowing all protocols to a router permits
DNS to that router and access to a router-hosted proxy. It is not a process-only
exception. An ICMP/admin-ports-only router policy may be offered separately.

## Local checks (no activation)

```sh
python3 -m unittest discover -s tests -v
bash menu-bar/build-preview.sh
```

Tests write only temporary state. The build writes only ignored `.build` output.
Neither command launches the preview, installs jobs, or changes PF/VPN settings.
