#!/bin/sh
# Read-only PF/VPN snapshot; does not print V2Box profile contents.
set -eu
printf 'VPN: '; scutil --nc status V2BOX 2>/dev/null | sed -n '1p'
printf '\nTunnel interfaces owned by V2BOX:\n'
ifconfig -v | awk '/^utun[0-9]+:/ {iface=$1; sub(/:/,"",iface)} /agent domain:NetworkExtension type:VPN.*desc:"VPN: V2BOX"/ {print iface}'
printf '\nPF state and active rules (sudo required):\n'
sudo pfctl -s info | sed -n '1,4p'
sudo pfctl -sr
printf '\nTransport peers owned by PacketTunnel, grouped without local ports:\n'
pid=$(pgrep -f '/Applications/V2Box.app/Contents/PlugIns/PacketTunnel.appex/Contents/MacOS/PacketTunnel' | head -1 || true)
if [ -n "$pid" ]; then
  lsof -nP -a -p "$pid" -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk 'NR>1 {split($9,a,"->"); split(a[2],b,":"); if (b[1] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) n[b[1]":"b[2]]++} END {for (x in n) print n[x],x}' | sort -nr
fi
