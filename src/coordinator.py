"""Offline refresh orchestration. Approval failure revokes stale permissions.

Injected diagnostics are best-effort and never control enforcement or Disable.
"""
from endpoints import EndpointApprovalRequired, approved_config
from policy import PolicyError, compile_quarantine


class Coordinator:
    def __init__(self, controller, audit=None):
        self.controller = controller
        self.audit = audit

    def event(self, stage, outcome, reason="none"):
        if self.audit is not None:
            try: self.audit(stage, outcome, reason)
            except Exception: pass  # Diagnostics must not prevent quarantine.

    def update(self, base, inventory, profile, now):
        try:
            config = approved_config(base, inventory, profile, now)
        except (PolicyError, TypeError, KeyError, AttributeError) as error:
            reason = "approval_required" if isinstance(error, EndpointApprovalRequired) else "policy_invalid"
            self.event("validate_approval", "failed", reason)
            try:
                compile_quarantine(base)
                quarantine_base = base
            except (PolicyError, TypeError, KeyError, AttributeError):
                quarantine_base = {}
            self.event("approval_quarantine", "started", reason)
            try:
                result = self.controller.quarantine(quarantine_base)
            except Exception:
                self.event("approval_quarantine", "failed", "enforcement_failed")
                raise
            self.event("approval_quarantine", "quarantined" if result["state"] == "on" else "skipped_disabled", reason)
            return {**result, "update_result": "approval_required_or_snapshot_invalid"}
        tunnel_reason = "tunnel_present" if config.get("tunnel") else "tunnel_absent"
        self.event("refresh_enforcement", "started", tunnel_reason)
        try:
            result = self.controller.refresh(config)
        except Exception:
            self.event("refresh_enforcement", "failed", "enforcement_failed")
            raise
        self.event("refresh_enforcement", "ok" if result["state"] == "on" else "skipped_disabled", tunnel_reason)
        return {**result, "update_result": "approved"}
