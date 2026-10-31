#!/usr/bin/env python3
"""Independent diagnostic observer. No PF writes, enable/disable or confirmation.

Waits for verified test activation, captures physical headers, then tests pinned
health and interface-bound direct TCP/DNS. All data stays in a root-private folder.
"""
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time

BASE = Path("/Library/Application Support/V2BoxGuard")
TEST = BASE / "first-test"
BACKEND = "/Library/PrivilegedHelperTools/org.v2boxkillswitch.backend"


def run(args, timeout=8):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def counter():
    text = run(["/sbin/pfctl", "-a", "com.p30arena.v2box-killswitch", "-vvsr"]).stdout
    target = False
    for line in text.splitlines():
        rule = re.sub(r"^@[0-9]+\s+", "", line.strip())
        if re.match(r"^@[0-9]+", line.strip()): target = False
        if rule.startswith("block drop out quick all") and 'label "v2box_default_deny"' in rule:
            target = True
        if target:
            match = re.search(r"Packets:\s*(\d+)", line)
            if match: return int(match.group(1))
    return None


def direct_probe(device, local, address, port, udp=False):
    # Darwin IP_BOUND_IF=25, from netinet/in.h. Never fall back to source binding.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(device))
        sock.bind((local, 0))
    except OSError:
        sock.close()
        return "inconclusive_binding_failed"
    try:
        if udp:
            query = struct.pack("!HHHHHH", 0x7135, 0x0100, 1, 0, 0, 0) + b"\x07example\x07invalid\x00\x00\x01\x00\x01"
            sock.sendto(query, (address, port))
            sock.recvfrom(1024)
        else:
            sock.connect((address, port))
        return "unexpected_success"
    except OSError:
        return "connection_failed"  # NOT proof of blocking by itself
    finally:
        sock.close()


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ["--observe"]: return 1
    report = {"probes": [], "health": "unverified", "ipv6": "not_tested", "verdict": "inconclusive"}
    captures = []
    handles = []
    try:
        until = time.monotonic() + 900
        while time.monotonic() < until:
            result = run([BACKEND, "status"])
            status = json.loads(result.stdout) if result.returncode == 0 else {}
            if status.get("state") == "on": break
            time.sleep(1)
        else:
            report["reason"] = "activation_not_observed"; return 0
        snapshot = json.loads((TEST / "snapshot.json").read_text())
        devices = snapshot["physical"]
        # Capture relevant packet HEADERS only, not payload or unrelated browsing.
        config = json.loads((BASE / "approved.json").read_text())
        peers = config["inventory"]["profiles"][config["profile"]]["endpoints"]
        clauses = ["(host 1.1.1.1 and (tcp port 44443 or udp port 53))", "udp port 53", "icmp"]
        for peer in peers:
            clauses.append(f'(host {peer["address"]} and tcp port {peer["port"]})')
        bpf = " or ".join(clauses)
        for device in devices:
            output = (TEST / ("capture-" + device + ".txt")).open("w")
            error = (TEST / ("capture-" + device + ".stderr")).open("w")
            handles.extend([output, error])
            proc = subprocess.Popen(["/usr/sbin/tcpdump", "-n", "-l", "-q", "-s", "96", "-i", device, bpf],
                                    stdout=output, stderr=error)
            captures.append((device, proc))
        time.sleep(1)
        for device, proc in captures:
            if proc.poll() is not None or "listening on" not in (TEST / ("capture-" + device + ".stderr")).read_text():
                report["reason"] = "capture_startup_failed"; return 0
        before = counter()
        for device in devices:
            result = run(["/usr/sbin/ipconfig", "getifaddr", device])
            if result.returncode: continue
            local = result.stdout.strip()
            for target, port, udp in [("1.1.1.1", 44443, False), ("1.1.1.1", 53, True)]:
                outcome = direct_probe(device, local, target, port, udp)
                report["probes"].append({"interface": device, "protocol": "dns" if udp else "tcp", "outcome": outcome})
            for gateway in snapshot.get("gateways", []):
                if gateway["interface"] == device and ":" not in gateway["address"]:
                    outcome = direct_probe(device, local, gateway["address"], 53, True)
                    report["probes"].append({"interface": device, "protocol": "router_dns", "outcome": outcome})
                    ping = run(["/sbin/ping", "-b", device, "-c", "1", "-W", "2000", gateway["address"]], timeout=4)
                    report["router_ping"] = "success" if ping.returncode == 0 else "failed_or_unverified"
        time.sleep(1)
        after = counter()
        report["block_counter_before"] = before
        report["block_counter_after"] = after
        sys.path.insert(0, BACKEND)
        from runtime import Runtime, run as native_run, read_config
        from health import HealthProbe
        runtime = Runtime(None, native_run, lambda: read_config(BASE))
        def health_run(args, timeout, env):
            return subprocess.run(args, timeout=timeout, env=env, capture_output=True, text=True)
        probe = HealthProbe("https://1.1.1.1/cdn-cgi/trace", "1.1.1.1", 200, health_run,
                            lambda dev: runtime.snapshot(config)["tunnel"] == dev)
        report["health"] = probe.check(snapshot["tunnel"]).health
        report["verdict"] = "review_required"
    except Exception as error:
        report["reason"] = type(error).__name__  # no raw profile/credential output
    finally:
        for _, proc in captures:
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=3)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        for handle in handles: handle.close()
        (TEST / "observation.json").write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__": raise SystemExit(main())
