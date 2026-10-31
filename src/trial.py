"""Pure conservative evaluation of a LIMITED IPv4 trial, never a full certification."""


def evaluate_ipv4_trial(report):
    """Return (passed, reason). Failed sockets alone are never sufficient.

    Root-owned observer supplies measured counters/capture evidence. This is not
    an authenticity mechanism and cannot certify routing/IPv6/boot/recovery.
    """
    if not isinstance(report, dict):
        return False, "invalid_report"
    if report.get("capture_started") is not True:
        return False, "capture_not_verified"
    drops = report.get("capture_kernel_drops")
    if not isinstance(drops, dict) or not drops or any(type(x) is not int or x != 0 for x in drops.values()):
        return False, "capture_loss_or_unknown"
    for field in ("outbound_dns_headers", "direct_tcp_probe_headers"):
        if type(report.get(field)) is not int or report[field] != 0:
            return False, "direct_packet_or_unknown"
    traffic = report.get("outbound_transport_headers")
    if type(traffic) is not int or traffic < 1:
        return False, "transport_not_observed"
    devices = report.get("ipv4_tested_interfaces")
    if (not isinstance(devices, list) or not devices or any(not isinstance(x, str) for x in devices)
            or not set(devices).issubset(drops)):
        return False, "missing_interface_coverage"
    probes = report.get("probes")
    if not isinstance(probes, list) or not probes:
        return False, "missing_probes"
    required = {"tcp", "dns", "router_dns"}
    if any(not isinstance(x, dict) or not isinstance(x.get("protocol"), str)
           or not isinstance(x.get("interface"), str) for x in probes):
        return False, "invalid_probe_record"
    for device in devices:
        attempted = [x for x in probes if isinstance(x, dict) and x.get("interface") == device]
        if {x.get("protocol") for x in attempted} != required:
            return False, "missing_required_probe"
    for probe in probes:
        if (not isinstance(probe, dict) or probe.get("interface") not in devices
                or probe.get("outcome") != "connection_failed"):
            return False, "probe_succeeded_or_unverified"
    before, after = report.get("block_counter_before"), report.get("block_counter_after")
    if (type(before) is not int or type(after) is not int or before < 0
            or after - before < len(probes)):
        return False, "block_counter_insufficient_or_reset"
    routers = report.get("router_ping_by_interface")
    if not isinstance(routers, dict) or any(routers.get(device) != "success" for device in devices):
        return False, "router_unverified"
    if report.get("health") != "usable" or report.get("router_ping") != "success":
        return False, "tunnel_or_router_unverified"
    return True, "limited_ipv4_checks_passed"
