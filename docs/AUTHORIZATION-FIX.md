# Authorization transfer failure — reproduced and fixed locally

## Symptom and reproduction

The menu's authorization-only request was rejected by the helper. A local diagnostic
using the same external-form verification reproduced -60005 (authorization denied).
Adding ExtendRights alone produced -60007 (interaction not allowed), not success.

The installed custom right delegated to authenticate-admin. macOS discarded the
intended wrapper timeout/shared values, and authenticate-admin itself has timeout 0.
The UI also used PreAuthorize, which can return success for non-preauthorizable
rights without a real grant. Together this was an unsuitable transfer design.

## Fix

- Define only our custom right as class=user, group=admin, authenticate-user=true,
  allow-root=false, shared=false, timeout=60, session-owner=false.
- Do NOT change Apple's authenticate-admin right or any unrelated security rule.
- UI obtains the actual right without PreAuthorize, keeps the authorization alive
  through the request, and destroys its rights afterwards.
- Helper uses ExtendRights without InteractionAllowed on the external form. It
  validates the exact granted right/name/flags and never silently accepts failure.
- Return sanitized stage/OSStatus diagnostics, never form bytes or credentials.

The custom right was explicitly migrated with its original definition backed up.
The Off-only helper/client were updated with old binaries retained for rollback.
No PF rule, enabled state or approved policy was modified.

## Validation

- Interactive local authorization -> external form -> verification: succeeds.
- A fresh unauthorized external form: rejected without any prompt.
- Pin/parser/anonymous IPC tests continue to pass.
- Backend reports Off and PF remains Disabled after update.
- The full signed client-to-root-helper menu action still requires user retest;
  local roundtrip success alone is not proof of that path.

Reproduce diagnostics (no PF operations):

```sh
bash menu-bar/test-authorization.sh --unauthorized-form-only
# Explicitly interactive; requires the custom right to be provisioned:
bash menu-bar/test-authorization.sh --interactive-authorization-only
```
