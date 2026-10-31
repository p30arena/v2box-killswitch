"""Explicit endpoint inventory, supporting several approved profiles.

No DNS is performed. A network/API result is NOT operator approval. Unknown peers
are refused; do not discover peers by allowing all sockets owned by a process.
"""
import copy
import math
from policy import PolicyError, compile_policy


class EndpointApprovalRequired(PolicyError):
    pass


def approved_config(base, inventory, active_profile, now):
    """Build a full replacement from an unexpired approved profile revision.

    Profile changes require a previously approved profile entry. Provider updates
    require a separately reviewed inventory update, not a fail-open DNS exception.
    Inventory is a local input; authentication/storage is a future helper concern.
    """
    if not isinstance(inventory, dict) or set(inventory) != {"version", "profiles"} or inventory["version"] != 1:
        raise PolicyError("invalid endpoint inventory")
    profiles = inventory["profiles"]
    if not isinstance(profiles, dict) or active_profile not in profiles:
        raise EndpointApprovalRequired("profile requires approval; no direct connectivity exception granted")
    entry = profiles[active_profile]
    if not isinstance(entry, dict) or set(entry) != {"revision", "expires_at", "endpoints"}:
        raise PolicyError("invalid profile inventory")
    expires = entry["expires_at"]
    if (type(expires) not in (int, float) or not math.isfinite(expires) or
            type(now) not in (int, float) or not math.isfinite(now)):
        raise PolicyError("invalid inventory timestamp")
    if expires <= now:
        raise EndpointApprovalRequired("endpoint approval expired; local approval required")
    if not isinstance(entry["revision"], str) or not entry["revision"]:
        raise PolicyError("missing revision")
    config = copy.deepcopy(base)
    config["endpoints"] = copy.deepcopy(entry["endpoints"])
    compile_policy(config)
    return config
