#!/bin/sh
# Requires a reviewed active policy. Directly binds IPv4 probes to the given NIC.
# A capture startup failure is an error, never a passing result.
set -eu
iface=${1:?usage: test-firewall-block.sh physical-interface}
case "$iface" in
  en[0-9]*) ;;
  *) echo 'Provide a physical Ethernet or Wi-Fi interface such as en0.' >&2; exit 2 ;;
esac
if ! ifconfig "$iface" >/dev/null 2>&1; then
  echo 'The named interface does not exist.' >&2
  exit 2
fi
local4=$(ipconfig getifaddr "$iface" 2>/dev/null || true)
if [ -z "$local4" ]; then echo 'No IPv4 address on interface; cannot run IPv4/DNS probes.' >&2; exit 2; fi
sudo -v
if ! sudo pfctl -s info | rg -q '^Status: Enabled'; then
  echo 'PF is disabled; refusing to send probes.' >&2
  exit 2
fi
rules=$(sudo pfctl -a com.p30arena.v2box-killswitch -sr)
if ! printf '%s\n' "$rules" | rg -q '^block drop out quick all$'; then
  echo 'Expected default-deny rule is not loaded; refusing to send probes.' >&2
  exit 2
fi
block_packets() {
  sudo pfctl -a com.p30arena.v2box-killswitch -vvsr | awk '
    {
      rule=$0
      sub(/^@[0-9]+[[:space:]]+/, "", rule)
      if (rule ~ /^block drop out quick all$/) target=1
      else if ($0 ~ /^@[0-9]+[[:space:]]/) target=0
    }
    target && /Packets:/ {
      if (match($0, /Packets:[[:space:]]*[0-9]+/)) {
        value=substr($0, RSTART, RLENGTH)
        gsub(/[^0-9]/, "", value)
        print value
        exit
      }
    }'
}
before=$(block_packets)
log=$(mktemp -t v2box-pf-capture)
sudo tcpdump -n -i "$iface" -l 'ip or ip6' >"$log" 2>&1 &
cap_pid=$!
cleanup() { kill "$cap_pid" 2>/dev/null || true; wait "$cap_pid" 2>/dev/null || true; cat "$log"; unlink "$log"; }
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
n=0
while [ "$n" -lt 20 ]; do
  if rg -q 'listening on ' "$log"; then break; fi
  if ! kill -0 "$cap_pid" 2>/dev/null; then echo 'tcpdump exited before capture began.' >&2; exit 2; fi
  sleep 0.1
  n=$((n + 1))
done
if ! rg -q 'listening on ' "$log"; then echo 'tcpdump did not confirm capture startup.' >&2; exit 2; fi

if nc -b "$iface" -n -G 3 -z 1.1.1.1 443; then echo 'FAIL: physical-interface IPv4 TCP succeeded'; exit 1; fi
if dig -b "$local4" +time=2 +tries=1 @1.1.1.1 example.com A >/dev/null 2>&1; then echo 'FAIL: direct DNS succeeded'; exit 1; fi
if route -n get -inet6 2606:4700:4700::1111 2>/dev/null | rg -q "interface: $iface"; then
  if nc -6 -b "$iface" -n -G 3 -z 2606:4700:4700::1111 443 2>/dev/null; then echo 'FAIL: physical-interface IPv6 TCP succeeded'; exit 1; fi
else
  echo 'SKIP: IPv6 probe; no physical route to the test destination.'
fi
sleep 1
after=$(block_packets)
if rg -q ' > (1\.1\.1\.1|2606:4700:4700::1111)\.' "$log"; then echo 'FAIL: a direct probe appeared on the physical interface'; exit 1; fi
if [ -z "$before" ] || [ -z "$after" ] || [ "$after" -le "$before" ]; then
  echo 'INCONCLUSIVE: PF block counter did not increase; probe failures may have another cause.' >&2
  exit 2
fi
echo "PASS: PF default-deny counter increased from $before to $after and probes were absent from the physical capture."
