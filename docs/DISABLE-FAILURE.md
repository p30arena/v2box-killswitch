# User-reported Disable failure — protection left Off

After the third limited trial, app update and removal of the active approval's
expiry, the user reported that menu Disable rejected their request. They used
`sudo pfctl -F all -d` to restore connectivity. This global operation can affect
unrelated PF rules/states/references and is NOT the project's recovery procedure.
Do not infer that the saved enable token is still an owned live reference afterward.

## Verified response

The operator durably wrote/read back explicit Off under the runtime/intent locks
to prevent helper refresh from undoing the user's intended disable. This response
made no PF rule/reference changes and did not release, reuse or clear the saved
PF token. Actual kernel queries then reported:

- PF disabled.
- Empty project anchor.
- Empty root filters, consistent with the user's global flush.

The private audit journal contained a `disable_enforcement` started event followed
by `disable_enforcement` failed / `enforcement_failed`. Thus the request reached
the backend; it was not merely hidden by the GUI capability preflight. The existing
coarse diagnostics do NOT identify whether scoped anchor removal, token release,
verification or another operation failed. No unverified cause is assigned.

The user's global flush destroys some pre-failure evidence. Do not reconstruct
an explanation from the current empty kernel rules or guess that token release
was the failing step. Off persistence alone is not proof of complete scoped
reference cleanup, and the stale token remains unresolved pending review.

## Upstream rotation hypothesis

The user reports that their V2Box VPN may change upstream periodically. The current
approval allows the exact numeric IP/port/protocol seen during preparation, not
all future peers. A different IP, transport, port, alternate server or DNS answer
could therefore cause intentional fail-closed loss of VPN connectivity. Removing
approval expiry did not implement endpoint rotation or approve a new endpoint.

This is plausible but not independently established for the reported outage. It
is separate from Disable reliability. The user explicitly rejected fixed-IP
allowlists, including larger endpoint inventories, as the wrong design. Do not
extend or reactivate this approach. No supported standalone application/provider-
aware replacement has been established. Native VPN kill-switch support would
require separate evaluation, not another PF approximation.

## Status and next work

Protection is intentionally Off after this incident. No new activation, VPN
restart, global PF operation, token reconciliation or recovery installation was
performed in response. The automatic start feature must not be confused with
fail-closed protection or endpoint approval. Repeated Disable and helper-failure
GUI recovery remain unproven; the observed failure supersedes prior limited
success as evidence of practical reliability. Public release stays withdrawn.

There is no planned further activation. The obsolete installed IP approval was
subsequently revoked/preserved privately under the runtime lock after verified
intent Off, PF disabled and an empty project anchor. No PF/token/VPN operation
was performed. Do not restore previously flushed root/Apple rules or references
blindly from an old backup.

The user has instead requested an unattended [reconnect tracker](RECONNECT-TRACKER.md),
explicitly not a kill switch. Source-only partial Disable changes were reverted
before that scope change was implemented; the old Disable defect is not claimed
fixed. The tracker does not call the old helper or depend on its Disable path.
