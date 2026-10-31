"""Offline user-session orchestration. NO executable, scheduler or transport.

The context reader MUST eventually use the pinned, authenticated native bridge.
Constructing RecoveryView is not authentication. Legacy status='on' is not enough.
This module is not wired into the installed app and must not be deployed alone.
Callbacks run on a serialized worker, never the GUI thread. No PF operations exist.
"""
from dataclasses import dataclass, replace
import math
import re
import threading
from typing import Optional

from health import HealthResult
from recovery import Recovery, RecoveryResult


@dataclass(frozen=True)
class RecoveryView:
    service_uuid: str
    epoch: str
    tunnel: Optional[str]
    tunnel_identity: Optional[str]
    requested_enabled: bool
    pf_enabled: bool
    gate_verified: bool
    approved_policy_matches: bool
    policy_mode: str


class _CommandGate:
    def __init__(self, owner): self.owner = owner
    def start(self): return self.owner._command("start")
    def stop(self): return self.owner._command("stop")


class SessionRecovery:
    def __init__(self, service_uuid, commands, read_context, probe=None,
                 allow_connected_restart=False, **recovery_options):
        if (not isinstance(service_uuid, str) or not re.fullmatch(
                r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", service_uuid)
                or getattr(commands, "service_uuid", None) != service_uuid):
            raise ValueError("locally approved service and matching command adapter required")
        if type(allow_connected_restart) is not bool:
            raise ValueError("explicit restart preference required")
        if allow_connected_restart and probe is None:
            raise ValueError("bound probe required for connected restarts")
        self.service_uuid = service_uuid
        self.commands = commands
        self.read_context = read_context
        self.probe = probe
        self.allow_connected_restart = allow_connected_restart
        self._lock = threading.Lock()
        self._last_now = None
        self._owner_thread = None
        self._binding = None
        self._expected = None
        self._expected_status = None
        self._refused = False
        self.recovery = Recovery(_CommandGate(self), **recovery_options)

    def _context(self):
        try: view = self.read_context()
        except Exception: return None
        if not isinstance(view, RecoveryView): return None
        if view.service_uuid != self.service_uuid or view.policy_mode != "approved": return None
        if any(flag is not True for flag in (view.requested_enabled, view.pf_enabled,
                                             view.gate_verified, view.approved_policy_matches)):
            return None
        if not isinstance(view.epoch, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", view.epoch): return None
        if view.tunnel is not None and (not isinstance(view.tunnel, str) or not re.fullmatch(r"utun[0-9]+", view.tunnel)):
            return None
        if view.tunnel is None:
            if view.tunnel_identity is not None: return None
        elif (not isinstance(view.tunnel_identity, str)
              or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", view.tunnel_identity)):
            return None
        return view

    def _status(self):
        if getattr(self.commands, "service_uuid", None) != self.service_uuid: return "Unknown"
        try: status = self.commands.status()
        except Exception: return "Unknown"
        return status if isinstance(status, str) and status in {
            "Connected", "Disconnected", "Connecting", "Disconnecting"} else "Unknown"

    def _forget_evidence(self):
        # Never carry a probe failure/transition timer across policy/tunnel epochs.
        # Retry budget/backoff deliberately survives, avoiding unlimited bursts.
        self._binding = None
        self.recovery.bad_health = 0
        self.recovery.transition_since = None

    def _idle(self, now, state):
        self._forget_evidence()
        return replace(self.recovery.tick(now, "Unknown", "unverified", False), state=state)

    def _command(self, action):
        # Recheck after sampling and immediately before each individual command.
        # This is NOT an atomic lease against a concurrent Disable. A native
        # cancellation/ordering protocol is still required before integration.
        if self._owner_thread != threading.get_ident() or self._expected is None:
            return False
        if self._context() != self._expected or self._status() != self._expected_status or self._context() != self._expected:
            self._refused = True
            return False
        if getattr(self.commands, "service_uuid", None) != self.service_uuid:
            self._refused = True
            return False
        return getattr(self.commands, action)() is True

    def tick(self, now):
        if type(now) not in (int, float) or not math.isfinite(now):
            raise ValueError("finite monotonic time required")
        if not self._lock.acquire(blocking=False):
            return RecoveryResult("busy", self.recovery.attempts, self.recovery.next_due)
        try:
            self._owner_thread = threading.get_ident()
            if self._last_now is not None and now < self._last_now:
                raise ValueError("monotonic clock went backwards")
            self._last_now = now
            view = self._context()
            if view is None: return self._idle(now, "context_unverified")
            binding = (view.service_uuid, view.epoch, view.tunnel, view.tunnel_identity)
            if binding != self._binding:
                self._forget_evidence()
                self._binding = binding
            status = self._status()
            if self._context() != view: return self._idle(now, "context_changed")
            health = "unverified"
            if status == "Connected" and self.allow_connected_restart:
                if view.tunnel is None: return self._idle(now, "tunnel_unverified")
                try:
                    result = self.probe.check(view.tunnel)
                    if isinstance(result, HealthResult) and result.health in {"usable", "unusable", "unverified"}:
                        health = result.health
                except Exception: pass  # Never log provider/probe exception text.
            if self._context() != view: return self._idle(now, "context_changed")
            self._expected, self._expected_status = view, status
            self._refused = False
            result = self.recovery.tick(now, status, health, True)
            if self._refused:
                self._forget_evidence()
                return replace(result, state="context_changed", action="none")
            return result
        finally:
            self._expected = self._expected_status = self._owner_thread = None
            self._lock.release()
