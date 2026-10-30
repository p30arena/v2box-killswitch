#!/bin/sh
set -eu
SERVICE=${V2BOX_SERVICE:-V2BOX}
status=$(scutil --nc status "$SERVICE" 2>/dev/null | sed -n '1p' || true)
printf 'VPN service: %s\n' "$SERVICE"
printf 'VPN status: %s\n' "${status:-Unavailable}"
if [ "$status" = "Connected" ]; then
  printf '\nConnected means macOS reports an active session; it does not verify useful end-to-end traffic.\n'
else
  printf '\nVPN is not connected.\n'
fi
printf '\nPF state (requires administrator privileges):\n'
if [ "$(id -u)" -eq 0 ]; then
  pfctl -s info 2>&1 | sed -n '1,4p'
else
  printf 'Not inspected; run: sudo pfctl -s info\n'
fi
