# Read-only root-to-user launch validation

`src/session_launch.py` builds only seven fixed Apple system identity queries.
It has no default runner and cannot select an arbitrary executable, shell, service
or VPN action. `tools/check_user_session_launch.py --check-only` is an explicit
root-only diagnostic; it does not install or register software.

## Launch arrangement

The fixed prefix is:

```
/bin/launchctl asuser <console-uid> /usr/bin/sudo -n -u #<console-uid> -- <fixed-identity-query>
```

This is an argv list, not a shell string. The UID is validated numeric non-root
console identity, not a user name or IPC request parameter. `asuser` adopts
bootstrap/audit context but does NOT drop credentials. The sudo step is necessary
to establish user UID/GID/group credentials. No interactive sudo prompt is allowed.
Only id UID/GID/groups and launchctl manageruid/managername queries are supported.
The environment is explicit and does not inherit proxy/DYLD/user configuration.

The diagnostic obtains the console owner from the kernel-owned console device
and expectations from account/group records. It checks Off state before/after and
refuses if console ownership changes during validation. Output is a fixed summary,
not raw account data, native errors, credentials or command output.

## Result actually observed

With explicit administrator-dialog approval, the read-only diagnostic succeeded:

- Target real and effective UID matched the non-root console user.
- Real and effective GID matched the account's primary group.
- Observed supplementary groups did not exceed the account group set.
- Bootstrap UID matched that user and manager name was Aqua.
- Protection stayed Off; PF Disabled; project anchor empty; no approved inventory
  or loaded/startup trial timer.
- No scutil, VPN command, PF write, installation or registration occurred.

No user-writable worker artifact was used for this root validation; only fixed
Apple system commands ran after the credential transition. The separate read-only
native worker remains uninstalled and its grant path cannot execute VPN commands.

## What this does NOT prove

This arrangement is not yet a trusted VPN executor. The launchctl/sudo chain has
not been certified for descendant ownership, cancellation or restart reconciliation.
A timeout or reaped outer launcher alone cannot prove all descendants are dead.
Do not turn this identity diagnostic into an arbitrary command runner, clear a
pending fence based on it, or wire it into menu Disable.

There is no root-owned worker deployment, durable child-lifecycle witness, actual
VPN execution, all-writer fence integration or usable unknown-state GUI recovery
in this change. The installed helper/app are unchanged. Automatic recovery remains
unavailable. Native audit-session details still need integration review; reading
bootstrap ownership is not an independent audit-session attestation.

Tests inject fake runners for rejected UID, wrong real/effective credentials,
unexpected groups, wrong bootstrap, errors and malformed output. The actual
administrator-launched check validates the identity transition only, not those
remaining lifecycle/security properties. No live protection trial was prepared.
