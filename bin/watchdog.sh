#!/bin/sh
# User-session watchdog. Only requests native reconnect; never touches PF.
set -eu
SERVICE=${V2BOX_SERVICE:-V2BOX}
LOGTAG=v2box-vpn-guard
LOCKFILE=${TMPDIR:-/tmp}/v2box-vpn-guard.lock

# Atomic PID lock; shlock removes a stale lock after a crashed/SIGKILLed run.
if ! /usr/bin/shlock -f "$LOCKFILE" -p "$$"; then
  exit 0
fi
trap 'unlink "$LOCKFILE" 2>/dev/null || true' EXIT HUP INT TERM

get_status() {
  scutil --nc status "$SERVICE" 2>/dev/null | sed -n '1p' || true
}

status=$(get_status)
case "$status" in
  Connected|Connecting|Reasserting|Disconnecting) exit 0 ;;
  Disconnected) ;;
  *) logger -t "$LOGTAG" "VPN '$SERVICE' status is '${status:-unavailable}'; retry deferred"; exit 0 ;;
esac

# Bounded retries; launchd invokes this again every five minutes if still down.
delay=5
attempt=1
while [ "$attempt" -le 4 ]; do
  status=$(get_status)
  case "$status" in
    Connected) logger -t "$LOGTAG" "VPN '$SERVICE' reports Connected"; exit 0 ;;
    Connecting|Reasserting|Disconnecting) exit 0 ;;
    Disconnected) ;;
    *) logger -t "$LOGTAG" "VPN '$SERVICE' status is '${status:-unavailable}'; retry deferred"; exit 0 ;;
  esac

  logger -t "$LOGTAG" "VPN '$SERVICE' disconnected; reconnect attempt $attempt/4"
  if output=$(scutil --nc start "$SERVICE" 2>&1); then
    :
  else
    logger -t "$LOGTAG" "Native reconnect request failed for '$SERVICE': $output"
  fi
  sleep "$delay"
  delay=$((delay * 2))
  attempt=$((attempt + 1))
done
logger -t "$LOGTAG" "VPN '$SERVICE' did not connect after four requests; retry deferred"
exit 0
