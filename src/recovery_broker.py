"""Offline ordering prototype, NOT a live root/XPC/session implementation.

Every participating writer must use the SAME transaction. Pending state fences
new automatic recovery, NOT explicit authorized protection Disable. The installed
Runtime/timer do not yet participate; native supervision is not integrated.
No native executor, lock, persistence or command runner is supplied by default.
"""
from dataclasses import dataclass
import re
import uuid


@dataclass(frozen=True)
class Peer:
    # Internal metadata from a verified NSXPC connection, never request fields.
    uid: int
    authenticated: bool


@dataclass(frozen=True)
class Context:
    # Fresh private approval + kernel/native evidence, read under transaction.
    service_uuid: str
    console_uid: int
    requested_enabled: bool
    pf_enabled: bool
    gate_verified: bool
    approved_policy_matches: bool
    policy_mode: str
    vpn_status: str


@dataclass(frozen=True)
class Completion:
    # Only a trusted supervisor may construct this proof after execution/reaping.
    # It must guarantee no descendant can start a command later.
    ticket: str
    uid: int
    terminated: bool
    exit_code: int


@dataclass(frozen=True)
class BrokerResult:
    state: str
    action: str = "none"


class RecoveryBroker:
    def __init__(self, transaction, pending_store, read_context, execute_and_reap,
                 disable_protection, new_ticket=lambda: uuid.uuid4().hex):
        self.transaction = transaction
        self.pending = pending_store
        self.read_context = read_context
        self.execute_and_reap = execute_and_reap
        self.disable_protection = disable_protection
        self.new_ticket = new_ticket

    @staticmethod
    def valid_context(context, peer):
        if not isinstance(peer, Peer) or peer.authenticated is not True or type(peer.uid) is not int or peer.uid <= 0:
            return False
        if not isinstance(context, Context): return False
        if type(context.console_uid) is not int or context.console_uid != peer.uid: return False
        if not isinstance(context.service_uuid, str) or not re.fullmatch(
                r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", context.service_uuid): return False
        return (context.policy_mode == "approved" and all(flag is True for flag in (
            context.requested_enabled, context.pf_enabled, context.gate_verified, context.approved_policy_matches)))

    @staticmethod
    def complete(result, ticket, uid):
        return (isinstance(ticket, str) and re.fullmatch(r"[a-f0-9]{32}", ticket) is not None
                and type(uid) is int and uid > 0
                and isinstance(result, Completion) and result.ticket == ticket
                and type(result.uid) is int and result.uid == uid
                and result.terminated is True and type(result.exit_code) is int)

    def request(self, action, peer):
        # No service UUID, endpoint, user name, path or command line is an IPC input.
        if action not in ("start", "stop"): return BrokerResult("request_rejected")
        with self.transaction():
            try:
                if self.pending.read() is not None: return BrokerResult("reconciliation_required")
                context = self.read_context()
            except Exception:
                return BrokerResult("context_unavailable")
            if not self.valid_context(context, peer): return BrokerResult("not_eligible")
            allowed = {"start": {"Disconnected"}, "stop": {"Connected", "Connecting", "Disconnecting"}}
            if not isinstance(context.vpn_status, str) or context.vpn_status not in allowed[action]:
                return BrokerResult("status_changed")
            if self.execute_and_reap is None: return BrokerResult("executor_unavailable")
            ticket = self.new_ticket()
            if not isinstance(ticket, str) or not re.fullmatch(r"[a-f0-9]{32}", ticket):
                return BrokerResult("ticket_unavailable")
            try:
                self.pending.write({"ticket": ticket, "uid": peer.uid})
            except Exception:
                return BrokerResult("pending_unavailable")
            # Hold the SAME lock through execution and proof of completion.
            # A timeout/exception is NOT proof that a user command is dead.
            try:
                result = self.execute_and_reap(action=action, service_uuid=context.service_uuid,
                                               uid=peer.uid, ticket=ticket, timeout=8)
            except Exception:
                return BrokerResult("reconciliation_required", action)
            if not self.complete(result, ticket, peer.uid):
                return BrokerResult("reconciliation_required", action)
            try: self.pending.clear(ticket, peer.uid)
            except Exception: return BrokerResult("reconciliation_required", action)
            return BrokerResult("completed" if result.exit_code == 0 else "command_failed", action)

    def disable(self):
        # Explicit authorized user action ONLY, never a recovery timeout/fallback.
        # NOT connected to the installed menu. Recovery-state corruption or an
        # unknown old child must not prevent removing protection at user's request.
        # A previously created VPN operation may finish; it cannot re-enable PF.
        with self.transaction():
            # The real controller persists Off FIRST. Enforcement errors propagate;
            # never invent an Off acknowledgement. Do not read/clear the fence here.
            return self.disable_protection()

    def reconcile(self, supervised_completion):
        # Internal supervisor callback, NEVER caller-supplied XPC completion data.
        with self.transaction():
            try: pending = self.pending.read()
            except Exception: return BrokerResult("pending_unavailable")
            if pending is None: return BrokerResult("nothing_pending")
            if (not isinstance(pending, dict) or set(pending) != {"ticket", "uid"}
                    or not self.complete(supervised_completion, pending["ticket"], pending["uid"])):
                return BrokerResult("reconciliation_required")
            try: self.pending.clear(pending["ticket"], pending["uid"])
            except Exception: return BrokerResult("reconciliation_required")
            return BrokerResult("reconciled")
