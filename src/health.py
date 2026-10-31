"""Pinned HTTPS health probe, injected runner only. No default execution.

A successful response verifies only this configured target at this instant, not
all internet connectivity, privacy, routing or PF enforcement. The tunnel verifier
must check current provider ownership, not merely that a utun name exists.
"""
from dataclasses import dataclass
import ipaddress
import re
import subprocess
from urllib.parse import urlsplit

from policy import PolicyError, interface


@dataclass(frozen=True)
class HealthResult:
    health: str
    reason: str


class HealthProbe:
    def __init__(self, url, address, expected_status, run, verify_tunnel):
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.port not in (None, 443)
                or parsed.query or parsed.fragment or "\\" in url
                or not re.fullmatch(r"[A-Za-z0-9.-]+", parsed.hostname)
                or any(ord(c) < 33 or ord(c) > 126 for c in url)):
            raise PolicyError("health URL requires HTTPS:443 without credentials, query or fragment")
        try:
            peer = ipaddress.ip_address(address)
        except ValueError as exc:
            raise PolicyError("health target must be pinned to a numeric IP") from exc
        if not peer.is_global or peer.is_multicast or getattr(peer, "ipv4_mapped", None):
            raise PolicyError("health target requires a global unicast IP")
        if type(expected_status) is not int or not 200 <= expected_status <= 299:
            raise PolicyError("explicit successful HTTP status required")
        self.url = url
        self.host = parsed.hostname
        self.address = str(peer)
        self.status = expected_status
        self.run = run
        self.verify_tunnel = verify_tunnel

    def check(self, tunnel):
        try:
            interface(tunnel, "utun")
            if self.verify_tunnel(tunnel) is not True:
                return HealthResult("unverified", "tunnel_identity_unverified")
        except Exception:
            return HealthResult("unverified", "tunnel_identity_unverified")
        address = f"[{self.address}]" if ":" in self.address else self.address
        args = ["/usr/bin/curl", "--disable", "--silent", "--show-error",
                "--noproxy", "*", "--proxy", "", "--interface", "if!" + tunnel,
                "--connect-timeout", "3", "--max-time", "5", "--proto", "=https",
                "--tlsv1.2", "--resolve", f"{self.host}:443:{address}",
                "--output", "/dev/null", "--write-out", "%{http_code} %{remote_ip}",
                "--url", self.url]
        try:
            result = self.run(args, timeout=7, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        except subprocess.TimeoutExpired:
            return HealthResult("unusable", "probe_timeout")
        except Exception:
            return HealthResult("unverified", "probe_execution_failed")
        if result.returncode in (2, 3, 4):
            return HealthResult("unverified", "probe_configuration_or_capability_error")
        if result.returncode:
            return HealthResult("unusable", "probe_failed")
        fields = result.stdout.strip().split()
        if len(fields) != 2:
            return HealthResult("unverified", "probe_output_invalid")
        try:
            observed = str(ipaddress.ip_address(fields[1]))
        except ValueError:
            return HealthResult("unverified", "probe_output_invalid")
        if fields[0] != str(self.status) or observed != self.address:
            return HealthResult("unusable", "unexpected_response")
        # Check ownership again to catch an observed interface replacement.
        try:
            if self.verify_tunnel(tunnel) is not True:
                return HealthResult("unverified", "tunnel_changed")
        except Exception:
            return HealthResult("unverified", "tunnel_changed")
        return HealthResult("usable", "target_reachable")
