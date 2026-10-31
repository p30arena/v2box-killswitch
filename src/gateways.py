"""Read-only IPv4 gateway discovery. No PF, DNS, sockets or privileged writes.

IPv6 gateway discovery is deliberately not implemented yet. A missing IPv4
scoped default returns no exception; it never falls back to the tunnel route.
"""
import ipaddress
import re
import subprocess
from policy import PolicyError, gateway_exceptions, interface


def parse_snapshot(device, route_text, interface_text):
    interface(device, "en")
    fields = dict(re.findall(r"^\s*(gateway|interface):\s*(\S+)\s*$", route_text, re.M))
    if fields.get("interface") != device or "gateway" not in fields:
        raise PolicyError("scoped route missing or interface mismatch")
    try:
        address = ipaddress.IPv4Address(fields["gateway"])
    except ValueError as exc:
        raise PolicyError("route gateway is not numeric IPv4") from exc
    if not re.match(r"^" + re.escape(device) + r":", interface_text):
        raise PolicyError("interface snapshot mismatch")
    if not re.search(r"^\s*status: active\s*$", interface_text, re.M):
        raise PolicyError("physical interface not active")
    matches = re.findall(r"^\s*inet\s+(\S+)\s+netmask\s+(0x[0-9a-fA-F]+|[0-9.]+)", interface_text, re.M)
    candidates = []
    for local, mask in matches:
        try:
            mask_text = str(ipaddress.IPv4Address(int(mask, 16))) if mask.startswith("0x") else mask
            subnet = ipaddress.IPv4Network(f"{local}/{mask_text}", strict=False)
        except ValueError as exc:
            raise PolicyError("invalid interface address or mask") from exc
        if address in subnet and str(address) != local:
            candidates.append({"interface": device, "address": str(address), "subnet": str(subnet)})
    if len(candidates) != 1:
        raise PolicyError("gateway not uniquely on-link")
    gateway_exceptions([device], candidates)
    return candidates[0]


def _run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=5, check=False)


def discover(device, run=_run):
    """Read twice to detect an observed route change during discovery.

    This reduces, but cannot eliminate, races. Activation needs a fresh snapshot
    and network-change monitoring. Exceptions must never accumulate indefinitely.
    """
    interface(device, "en")
    args = ["/sbin/route", "-n", "get", "-ifscope", device, "default"]
    first = run(args)
    info = run(["/sbin/ifconfig", device])
    second = run(args)
    if any(x.returncode for x in (first, info, second)):
        raise PolicyError("scoped gateway discovery failed")
    before = parse_snapshot(device, first.stdout, info.stdout)
    after = parse_snapshot(device, second.stdout, info.stdout)
    if before != after:
        raise PolicyError("network changed during discovery; retry")
    return after
