"""Offline PF policy compiler. Never reads the host network or invokes pfctl.

Input addresses are explicit operator approvals, not discovered from sockets.
Output is experimental and must not be installed without macOS validation.
"""
import ipaddress
import re


class PolicyError(ValueError):
    pass


def interface(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(prefix + r"[0-9]+", value):
        raise PolicyError("invalid interface")
    return value


def gateway_exceptions(physical, gateways):
    """Validate a future adapter's gateway snapshot; do not query this Mac.

    Each gateway must be a private/link-local on-link unicast host on a named
    physical interface. Never infer a gateway from the VPN's default route.
    """
    result = set()
    private = [ipaddress.ip_network(x) for x in
               ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10")]
    for entry in gateways:
        if set(entry) != {"interface", "address", "subnet"}:
            raise PolicyError("gateway requires interface, address and subnet")
        dev = interface(entry["interface"], "en")
        if dev not in physical:
            raise PolicyError("gateway must use an approved physical interface")
        try:
            addr = ipaddress.ip_address(entry["address"])
            net = ipaddress.ip_network(entry["subnet"], strict=True)
        except ValueError as exc:
            raise PolicyError("invalid gateway snapshot") from exc
        if (addr.version != net.version or addr not in net or
                not any(addr.version == n.version and addr in n for n in private) or
                (addr.version == 4 and addr in (net.network_address, net.broadcast_address))):
            raise PolicyError("gateway must be a private/link-local on-link host")
        result.add((dev, addr.version, str(addr)))
    return sorted(result)


def compile_policy(config):
    """Return deterministic rules; reject the entire update on invalid input.

    A missing tunnel yields a transport-only/default-deny policy. A missing
    endpoint inventory is an error, not permission to retain old tunnel passes.
    """
    if set(config) - {"physical", "tunnel", "endpoints", "lan", "gateways"}:
        raise PolicyError("unknown configuration field")
    physical = sorted(set(interface(x, "en") for x in config.get("physical", [])))
    if not physical:
        raise PolicyError("explicit physical interface inventory required")
    gateways = gateway_exceptions(physical, config.get("gateways", []))
    tun = config.get("tunnel")
    if tun is not None:
        tun = interface(tun, "utun")
    endpoints = set()
    for entry in config.get("endpoints", []):
        if set(entry) != {"address", "port", "protocol"}:
            raise PolicyError("endpoint requires address, port and protocol")
        try:
            address = ipaddress.ip_address(entry["address"])
        except ValueError as exc:
            raise PolicyError("endpoint must be a numeric IP; DNS bootstrap is not implemented") from exc
        if not address.is_global or getattr(address, "ipv4_mapped", None):
            raise PolicyError("endpoint must be global unicast")
        port = entry["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise PolicyError("invalid port")
        proto = entry["protocol"]
        if proto not in ("tcp", "udp"):
            raise PolicyError("unsupported transport")
        endpoints.add((address.version, str(address), port, proto))
    if not endpoints:
        raise PolicyError("approved endpoints required")

    # Only explicit private/link-local subnets, never all RFC1918 automatically.
    lans = set()
    allowed = [ipaddress.ip_network(x) for x in
               ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10")]
    for value in config.get("lan", []):
        try:
            net = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise PolicyError("invalid LAN subnet") from exc
        if not any(net.version == a.version and net.subnet_of(a) for a in allowed):
            raise PolicyError("LAN exceptions must be private or link-local subnets")
        lans.add((net.version, str(net)))

    rules = ["# EXPERIMENTAL OFFLINE OUTPUT — NOT VALIDATED FOR DEPLOYMENT",
             "pass out quick on lo0 all no state"]
    if tun:
        rules.append(f"pass out quick on {tun} all no state")
    for dev, version, address in gateways:
        family = "inet" if version == 4 else "inet6"
        rules.append(f"pass out quick on {dev} {family} to {address} no state")
    for dev in physical:
        for version, address, port, proto in sorted(endpoints):
            family = "inet" if version == 4 else "inet6"
            # Stateless deliberately: removing an approved endpoint must not leave
            # an old PF state granting access. No floating state across interfaces.
            flags = " flags any" if proto == "tcp" else ""
            rules.append(f"pass out quick on {dev} {family} proto {proto} to {address} port {port}{flags} no state")
        for version, subnet in sorted(lans):
            family = "inet" if version == 4 else "inet6"
            rules.append(f"pass out quick on {dev} {family} to {subnet} no state")
        rules.extend([
            f"pass out quick on {dev} inet proto udp from any port 68 to 255.255.255.255 port 67 no state",
            f"pass out quick on {dev} inet6 proto udp from any port 546 to ff02::1:2 port 547 no state",
            f"pass out quick on {dev} inet6 proto icmp6 to fe80::/10 icmp6-type {{ 133, 135, 136 }} no state",
            f"pass out quick on {dev} inet6 proto icmp6 to ff02::/16 icmp6-type {{ 133, 135, 136 }} no state",
        ])
    rules.append('block drop out quick all label "v2box_default_deny"')
    return "\n".join(rules) + "\n"
