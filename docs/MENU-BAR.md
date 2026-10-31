# Menu-bar controller requirements (not implemented)

The replacement needs a native macOS menu-bar application. Users must not need
Terminal to recover connectivity. This is a deployment prerequisite, not an
optional future convenience.

## Menu

- Protection: On / Off / Error / Unverified (read back actual enforcement state).
- VPN: Connected / Disconnected; separately show whether health was verified.
- Enable Protection…: explicit confirmation and authorization for privileged work.
- Disable Protection…: warn that direct traffic can escape; persist disabled intent,
  stop the refresh loop, and remove only this project's enforcement. Never globally
  flush PF or disable another product's firewall. Confirm actual removal before
  displaying Off. A failed removal must display Error, not Off.
- Reconnect VPN: request recovery without disabling enforcement.
- Diagnostics: redacted status and errors, not credentials or profile contents.
- Quit: exits UI only; protection remains active. State this explicitly.

## Privilege and recovery design

UI is unprivileged. A small, signed, root-owned helper exposes only fixed enable,
disable, status and reconnect operations over an authenticated local IPC channel.
No arbitrary shell commands, executable paths, anchor names or rule text from the UI.
Authorization mechanism and signing/installation requirements must be validated
against the supported macOS releases before implementing privileged operations.

Disable intent must be serialized with refresh so a concurrent refresh cannot
reinstall blocking rules after disable. It must survive helper restart and boot.
PF enable tokens must be tracked and released only if owned by this helper.
Removing this project's blocking anchor, not a global PF reset, is the primary
way to stop its enforcement. Preserve unrelated rules, states and PF owners.

Do not ship a working-looking status icon with nonfunctional recovery actions.
Test helper crash, UI crash, concurrent enable/disable, stale tokens, missing UI,
permission denial and restart after disable before any live installation.

## Current status

Specification only. No menu-bar app or privileged helper has been installed or
implemented. The offline policy compiler does not provide this controller.
