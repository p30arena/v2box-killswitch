"""Experimental scoped PF driver, with an explicitly injected command runner.

Only fake-kernel tests exercise mutation so far. Runtime integration is provided
by runtime.py but is not installed or live-validated. Restart reconciliation and
end-to-end validation remain deployment blockers. Caller must serialize access
and provide trusted durable token storage and a trusted runner.
"""
import re
from controller import ControllerError

ANCHOR = "com.p30arena.v2box-killswitch"
PFCTL = "/sbin/pfctl"


class PFDriver:
    def __init__(self, run, tokens):
        self.run = run
        self.tokens = tokens

    def _call(self, *args, text=None):
        result = self.run([PFCTL, *args], input=text)
        if result.returncode:
            raise ControllerError("PF operation failed; actual enforcement must be inspected")
        return result.stdout

    def _root_has_gate(self):
        # A quick root anchor prevents later Apple/user pass rules overriding our
        # final deny. Reject earlier filters rather than guessing their effects.
        root = self._call("-sr")
        lines = [x.strip() for x in root.splitlines() if x.strip() and not x.startswith("#")]
        return bool(lines and re.fullmatch(
            r'anchor "' + re.escape(ANCHOR) + r'" (?:quick|quick all|all quick)', lines[0]))

    def snapshot(self):
        info = self._call("-s", "info")
        if not re.search(r"(?m)^Status: (Enabled|Disabled)\b", info):
            raise ControllerError("unrecognized PF status")
        rules = self._call("-a", ANCHOR, "-sr")
        return {"pf_enabled": bool(re.search(r"(?m)^Status: Enabled\b", info)),
                # Conservative: any rules left means Disable is incomplete.
                "anchor_active": bool(rules.strip()),
                "gate_verified": self._root_has_gate(),
                "policy_mode": "quarantine" if 'label "v2box_quarantine"' in rules else "approved"}

    def replace(self, rules):
        if not self._root_has_gate():
            raise ControllerError("first quick root anchor is not verified; refusing update")
        if not rules.endswith('block drop out quick all label "v2box_default_deny"\n'):
            raise ControllerError("missing final default deny")
        # stdin avoids writable temporary rule paths. Never reload /etc/pf.conf.
        expected = self._call("-n", "-v", "-a", ANCHOR, "-f", "-", text=rules)
        if not expected.strip():
            raise ControllerError("PF did not return canonical rules")
        self._call("-a", ANCHOR, "-f", "-", text=rules)
        observed = self._call("-a", ANCHOR, "-sr")
        if observed.strip() != expected.strip():
            raise ControllerError("complete PF replacement read-back differs from canonical policy")

    def acquire(self):
        record = self.tokens.read()
        if record == "pending":
            raise ControllerError("PF token acquisition outcome unknown; do not acquire again")
        if record is not None:
            # A persisted token is not proof it is still valid in this boot.
            # Reconciliation is required; never silently acquire another token.
            if not re.fullmatch(r"[0-9]+", record):
                raise ControllerError("invalid owned PF token")
            if not self.snapshot()["pf_enabled"]:
                raise ControllerError("owned token is stale; explicit reconciliation required")
            return
        self.tokens.write("pending")  # crash before recording token is detectable
        result = self.run([PFCTL, "-E"], input=None)
        combined = result.stdout + "\n" + result.stderr
        match = re.search(r"(?m)^Token\s*:\s*([0-9]+)\s*$", combined)
        if result.returncode or not match:
            raise ControllerError("PF enable outcome unknown; token reconciliation required")
        self.tokens.write(match.group(1))

    def remove(self):
        # Empty ONLY our anchor. No global flush, state clearing or PF disable.
        self._call("-a", ANCHOR, "-f", "-", text="")
        if self._call("-a", ANCHOR, "-sr").strip():
            raise ControllerError("project anchor removal not confirmed")

    def release(self):
        token = self.tokens.read()
        if token is None:
            return
        if token == "pending" or not re.fullmatch(r"[0-9]+", token):
            # Removing our rules still recovers access; never guess a token.
            raise ControllerError("owned token unknown; anchor removed but cleanup incomplete")
        self._call("-X", token)
        self.tokens.write(None)
