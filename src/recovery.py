"""Nonblocking VPN recovery core. No PF, GUI, network probes or command execution.

The future user-session service supplies monotonic time, fresh VPN status,
interface-bound health evidence and an injected VPN command adapter. All delays
are represented as next_due, never blocking sleeps. One owner must serialize tick.
"""
from dataclasses import dataclass
import math


@dataclass(frozen=True)
class RecoveryResult:
    state: str
    attempts: int
    next_due: float
    action: str = "none"


class Recovery:
    def __init__(self, commands, max_attempts=4, base_delay=5, max_delay=60,
                 cooldown=300, transition_timeout=60, unhealthy_threshold=3):
        if (type(max_attempts) is not int or max_attempts < 1 or
                type(unhealthy_threshold) is not int or unhealthy_threshold < 1):
            raise ValueError("positive retry limits required")
        for value in (base_delay, max_delay, cooldown, transition_timeout):
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise ValueError("positive finite recovery delays required")
        self.commands = commands
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.cooldown = cooldown
        self.transition_timeout = transition_timeout
        self.threshold = unhealthy_threshold
        self.attempts = 0
        self.next_due = 0
        self.transition_since = None
        self.bad_health = 0
        self.last_now = None

    def tick(self, now, vpn_status, health, enforcement_verified):
        """health = usable/unusable/unverified, independently of VPN status.

        Fresh evidence must be supplied on every tick. Unverified health never
        causes a restart. Unknown status never causes commands. If no trusted
        enforcement, fail safe by declining automated networking changes.
        """
        if type(now) not in (int, float) or not math.isfinite(now):
            raise ValueError("finite monotonic time required")
        if self.last_now is not None and now < self.last_now:
            raise ValueError("monotonic clock went backwards")
        self.last_now = now
        if health not in ("usable", "unusable", "unverified"):
            raise ValueError("invalid health evidence")

        def result(state, action="none"):
            return RecoveryResult(state, self.attempts, self.next_due, action)

        if enforcement_verified is not True:
            self.bad_health = 0
            self.transition_since = None
            return result("enforcement_unverified")
        if vpn_status == "Connected" and health == "usable":
            self.attempts = 0
            self.next_due = now
            self.bad_health = 0
            self.transition_since = None
            return result("healthy")
        if vpn_status not in ("Connected", "Disconnected", "Connecting", "Disconnecting"):
            self.bad_health = 0
            self.transition_since = None
            return result("status_unknown")
        if vpn_status in ("Connecting", "Disconnecting"):
            self.bad_health = 0
            if self.transition_since is None:
                self.transition_since = now
            if now - self.transition_since < self.transition_timeout or now < self.next_due:
                return result("transitioning")
            action = "stop"
        else:
            self.transition_since = None
            if vpn_status == "Connected":
                if health != "unusable":
                    self.bad_health = 0
                    return result("health_unverified")
                self.bad_health += 1
                if self.bad_health < self.threshold:
                    return result("health_suspect")
                action = "stop"
            else:
                self.bad_health = 0
                action = "start"

        if now < self.next_due:
            return result("backoff")
        if self.attempts >= self.max_attempts:
            # A bounded retry burst followed by cooldown; try another burst only
            # on a later tick, never spin in a command loop.
            self.attempts = 0
            self.next_due = now + self.cooldown
            self.bad_health = 0
            return result("cooldown")
        self.attempts += 1
        self.next_due = now + min(self.max_delay, self.base_delay * (2 ** (self.attempts - 1)))
        try:
            succeeded = getattr(self.commands, action)()
        except Exception:
            # Never log raw provider errors/profile data in this core.
            return result("command_failed", action)
        if succeeded is not True:
            return result("command_failed", action)
        if action == "stop":
            self.bad_health = 0
            self.transition_since = now
        return result("recovery_requested", action)
