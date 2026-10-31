"""Native VPN command adapter with injected runner only; no execution defaults.

Runs in the user's session in a future integration, not via unauthenticated UI
shell input. Service UUID is a locally approved preference, not an IPC parameter.
"""
import re


class VPNCommands:
    def __init__(self, service_uuid, run):
        if not isinstance(service_uuid, str) or not re.fullmatch(
                r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", service_uuid):
            raise ValueError("registered VPN service UUID required")
        self.service_uuid = service_uuid
        self.run = run

    def _command(self, action):
        result = self.run(["/usr/sbin/scutil", "--nc", action, self.service_uuid], timeout=8)
        return result.returncode == 0

    def start(self): return self._command("start")
    def stop(self): return self._command("stop")

    def status(self):
        result = self.run(["/usr/sbin/scutil", "--nc", "status", self.service_uuid], timeout=8)
        if result.returncode:
            return "Unknown"
        first = result.stdout.splitlines()[0].strip() if result.stdout.splitlines() else ""
        return first if first in ("Connected", "Disconnected", "Connecting", "Disconnecting") else "Unknown"
