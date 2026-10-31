"""Fixed JSON-friendly backend API, without executable/installation entrypoint.

A future root deployment supplies the Controller and trusted backend. This API
never accepts PF rules, endpoints, paths, shell commands, or service names.
Enable and reconnect remain deliberately unavailable pending safety integration.
"""


class BackendAPI:
    def __init__(self, controller):
        self.controller = controller

    def _reply(self, status):
        return {"state": status.get("state", "error"),
                "policy_mode": status.get("policy_mode", "unknown"),
                "vpn_health": "unverified",
                "can_enable": "false", "can_disable": "false" if status.get("state") == "off" else "true",
                "can_reconnect": "false"}

    def dispatch(self, operation):
        if operation == "status":
            try:
                return self._reply(self.controller.status())
            except Exception:
                # A broken intent file must not hide the Disable recovery action.
                return self._reply({"state": "error"})
        if operation == "disable":
            # Failure must propagate: never claim Off if removing our rules or
            # verifying the resulting state failed.
            return self._reply(self.controller.disable())
        raise ValueError("operation unavailable")
