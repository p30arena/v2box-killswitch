#!/usr/bin/env python3
"""Root read-only networking inspection plus private backups; no rule changes."""
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess

BASE = Path("/Library/Application Support/V2BoxGuard")


def run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=15, check=False)


def save(directory, name, text):
    path = directory / name
    path.write_text(text)
    path.chmod(0o600)


def main():
    if os.geteuid() != 0:
        raise SystemExit("root required for backup/inspection")
    directory = BASE / "state" / ("preflight-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    directory.mkdir(mode=0o700)
    shutil.copyfile("/etc/pf.conf", directory / "pf.conf")
    (directory / "pf.conf").chmod(0o600)
    collected = {}
    for label, args in {
        "pf-info": ["/sbin/pfctl", "-s", "info"],
        "pf-root": ["/sbin/pfctl", "-sr"],
        "pf-states": ["/sbin/pfctl", "-s", "states"],
        "pf-interfaces": ["/sbin/pfctl", "-s", "Interfaces", "-v"],
        "project-anchor": ["/sbin/pfctl", "-a", "com.p30arena.v2box-killswitch", "-sr"],
    }.items():
        result = run(args)
        if result.returncode: raise SystemExit("Inspection failed: " + label)
        save(directory, label + ".txt", result.stdout)
        collected[label] = result.stdout
    services = run(["/usr/sbin/scutil", "--nc", "list"]).stdout
    match = re.search(r'(?m)^.*\s([0-9A-Fa-f-]{36})\s+VPN\s+\(hossin\.asaadi\.V2Box\)\s+"([^"]+)"', services)
    if not match: raise SystemExit("V2Box service not uniquely identifiable")
    uuid, name = match.groups()
    data = run(["/usr/sbin/scutil", "--nc", "status", uuid]).stdout
    profile = data[data.find('"profile" : {'):] if '"profile" : {' in data else ""
    host = re.search(r'"server"\s*:\s*"([^"\\]+)"', profile)
    port = re.search(r'"serverPort"\s*:\s*"?(\d{1,5})"?', profile)
    if not host or not port: raise SystemExit("Endpoint not identifiable without exposing profile")
    host_value, port_value = host.group(1), int(port.group(1))
    addresses = sorted({str(ipaddress.ip_address(x[4][0])) for x in socket.getaddrinfo(host_value, port_value, 0, socket.SOCK_STREAM)})
    processes = run(["/bin/ps", "-axo", "pid=,comm="]).stdout
    pids = []
    for line in processes.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) == 2 and "V2Box.app/" in fields[1] and "PacketTunnel" in fields[1]:
            pids.append(fields[0])
    peers = []
    for pid in pids:
        result = run(["/usr/sbin/lsof", "-nP", "-a", "-p", pid, "-i", "-F", "PnT"])
        protocol = None
        for line in result.stdout.splitlines():
            if line.startswith("P"): protocol = line[1:].lower()
            if line.startswith("n") and "->" in line:
                peer = re.search(r'->(?:\[([^]]+)\]|([^:]+)):(\d+)$', line)
                if peer:
                    try: address = str(ipaddress.ip_address(peer.group(1) or peer.group(2)))
                    except ValueError: continue
                    entry = {"address": address, "port": int(peer.group(3)), "protocol": protocol}
                    if entry not in peers: peers.append(entry)
    approved = [p for p in peers if p["address"] in addresses and p["port"] == port_value and p["protocol"] == "tcp"]
    summary = {"service_uuid": uuid, "service_name": name,
               "vpn_status": data.splitlines()[0] if data else "Unknown",
               "configured_host": host_value, "configured_port": port_value,
               "resolved_addresses": addresses, "observed_peers": peers,
               "matching_transport_peers": approved}
    save(directory, "discovery.json", json.dumps(summary, indent=2))
    print(json.dumps({"private_backup": str(directory), "vpn_status": summary["vpn_status"],
                      "pf_enabled": "Status: Enabled" in collected["pf-info"],
                      "existing_state_count": len(collected["pf-states"].splitlines()),
                      "skip_flags_present": bool(re.search(r'\bskip\b', collected["pf-interfaces"], re.I)),
                      "matching_transport_peer_count": len(approved), "provider_process_count": len(pids)}))


if __name__ == "__main__": main()
