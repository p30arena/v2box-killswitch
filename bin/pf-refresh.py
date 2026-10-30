#!/usr/bin/python3
"""Root helper: refresh only our PF anchor and maintain its PF enable reference."""
import ipaddress
import pathlib
import re
import socket
import subprocess
import sys
import time

ANCHOR = "com.p30arena.v2box-killswitch"
RULE_FILE = pathlib.Path("/etc/pf.anchors/com.p30arena.v2box-killswitch")
LOG = "/usr/bin/logger"
SERVICE = __import__("os").environ.get("V2BOX_SERVICE", "V2BOX")


def run(args, timeout=8):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, check=False)


def vpn_config():
    result = run(["/usr/sbin/scutil", "--nc", "status", SERVICE])
    if result.returncode:
        raise RuntimeError("cannot read V2BOX configuration")
    marker = result.stdout.find('"profile" : {')
    host_value = None
    port_value = None
    if marker >= 0:
        section = result.stdout[marker:]
        host = re.search(r'"server"\s*:\s*"([^"\\]+)"', section)
        port = re.search(r'"serverPort"\s*:\s*"?(\d{1,5})"?', section)
        if host and port:
            host_value, port_value = host.group(1), port.group(1)
    if not host_value:
        # Some macOS releases omit the provider's profile payload from status.
        # Supply this root-owned file as: hostname port
        endpoint_file = pathlib.Path("/etc/v2box-killswitch/endpoint")
        try:
            fields = endpoint_file.read_text().strip().split()
            if len(fields) == 2:
                host_value, port_value = fields
        except OSError:
            pass
    if not host_value or not port_value or not port_value.isdigit():
        raise RuntimeError("endpoint unavailable; configure /etc/v2box-killswitch/endpoint")
    port_num = int(port_value)
    if not 1 <= port_num <= 65535:
        raise RuntimeError("invalid V2BOX endpoint port")
    addresses = set()
    try:
        addresses.add(str(ipaddress.ip_address(host_value)))
    except ValueError:
        for family, _, _, _, sockaddr in socket.getaddrinfo(host_value, port_num, 0, socket.SOCK_STREAM):
            if family in (socket.AF_INET, socket.AF_INET6):
                addresses.add(str(ipaddress.ip_address(sockaddr[0].split("%", 1)[0])))
    if not addresses:
        raise RuntimeError("V2BOX endpoint did not resolve")
    return sorted(addresses, key=lambda item: (":" in item, item)), port_num


def physical_interfaces():
    data = run(["/usr/sbin/networksetup", "-listallhardwareports"])
    devices = re.findall(r"(?m)^Device: (en\d+)$", data.stdout)
    active = []
    for dev in devices:
        info = run(["/sbin/ifconfig", "-v", dev]).stdout
        if "status: active" in info and ("\n\tinet " in info or "\n\tinet6 " in info):
            active.append(dev)
    if not active:
        raise RuntimeError("no active physical en* interface found")
    return sorted(set(active))


def tunnel_interface():
    data = run(["/sbin/ifconfig", "-v"]).stdout
    current = None
    for line in data.splitlines():
        header = re.match(r"^(utun\d+):", line)
        if header:
            current = header.group(1)
        if current and 'desc:"VPN: V2BOX"' in line and "NetworkExtension type:VPN" in line:
            return current
    return None


def generate():
    peers, port = vpn_config()
    physical = physical_interfaces()
    tun = tunnel_interface()
    phys_macro = "{ " + " ".join(physical) + " }"
    v4 = [p for p in peers if ":" not in p]
    v6 = [p for p in peers if ":" in p]
    lines = [f'physical_if = "{phys_macro}"', f'peer_port = "{port}"',
             "pass out quick on lo0 all no state"]
    if tun:
        lines.append(f"pass out quick on {tun} all no state")
    if v4:
        peers4 = "{ " + " ".join(v4) + " }"
        lines.append(f"pass out quick on $physical_if inet proto tcp to {peers4} port $peer_port flags any keep state (if-bound)")
    if v6:
        peers6 = "{ " + " ".join(v6) + " }"
        lines.append(f"pass out quick on $physical_if inet6 proto tcp to {peers6} port $peer_port flags any keep state (if-bound)")
    lines += [
        "pass out quick inet proto udp from any port 68 to any port 67 keep state",
        "pass out quick inet6 proto udp from any port 546 to ff02::1:2 port 547 keep state",
        "block drop out quick all",
    ]
    return "\n".join(lines) + "\n"


def ensure_pf_enabled():
    info = run(["/sbin/pfctl", "-s", "info"])
    if "Status: Disabled" in info.stdout:
        enabled = run(["/sbin/pfctl", "-E"])
        if enabled.returncode:
            raise RuntimeError("could not enable PF")
        subprocess.run([LOG, "-t", "v2box-pf-refresh", "enabled PF with the loaded fail-closed rules"], check=False)


def refresh():
    text = generate()
    current = RULE_FILE.read_text() if RULE_FILE.exists() else None
    if text != current:
        temp = RULE_FILE.with_suffix(".tmp")
        temp.write_text(text)
        temp.chmod(0o600)
        check = run(["/sbin/pfctl", "-n", "-a", ANCHOR, "-f", str(temp)])
        if check.returncode:
            temp.unlink(missing_ok=True)
            raise RuntimeError("generated PF anchor failed syntax validation")
        temp.replace(RULE_FILE)
        applied = run(["/sbin/pfctl", "-a", ANCHOR, "-f", str(RULE_FILE)])
        if applied.returncode:
            raise RuntimeError("could not refresh PF anchor")
        subprocess.run([LOG, "-t", "v2box-pf-refresh", "refreshed V2BOX tunnel and endpoint rules"], check=False)
    ensure_pf_enabled()


def main():
    once = "--once" in sys.argv
    while True:
        try:
            refresh()
        except Exception as exc:
            subprocess.run([LOG, "-t", "v2box-pf-refresh", f"refresh failed; default block retained: {exc}"], check=False)
        try:
            ensure_pf_enabled()
        except Exception as exc:
            subprocess.run([LOG, "-t", "v2box-pf-refresh", f"PF enable failed: {exc}"], check=False)
        if once:
            return
        time.sleep(10)


if __name__ == "__main__":
    main()
