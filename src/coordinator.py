"""Offline-testable refresh orchestration. No service/network loop or activation.

The future helper supplies fresh trusted snapshots. Approval failure revokes old
permissions instead of retaining a stale endpoint/tunnel pass. Explicit Disable
always wins through Controller's lock and persisted intent.
"""
from endpoints import approved_config
from policy import PolicyError, compile_quarantine


class Coordinator:
    def __init__(self, controller):
        self.controller = controller

    def update(self, base, inventory, profile, now):
        try:
            config = approved_config(base, inventory, profile, now)
        except (PolicyError, TypeError, KeyError, AttributeError):
            # No endpoint values or provider payloads in returned error/log text.
            # If even router discovery is invalid, keep loopback and deny only.
            try:
                compile_quarantine(base)
                quarantine_base = base
            except (PolicyError, TypeError, KeyError, AttributeError):
                quarantine_base = {}
            result = self.controller.quarantine(quarantine_base)
            return {**result, "update_result": "approval_required_or_snapshot_invalid"}
        result = self.controller.refresh(config)
        return {**result, "update_result": "approved"}
