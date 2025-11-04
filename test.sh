#!/bin/bash
# monitor+freq setter

set -euo pipefail
wlan="${1:-wlx00c0cab3e15f}"
ch="${2:-1}"
txp="${3:-20}"     # dBm

ch2mhz(){
  [[ "$1" =~ ^[0-9]+$ && $1 -ge 2300 ]] && { echo "$1"; return; }
  (( $1>=1 && $1<=14 )) && echo $((2407+5*$1)) || echo $((5000+5*$1))
}

mhz="$(ch2mhz "$ch")"
mbm=$((txp*100))

ip link set "$wlan" down
iw dev "$wlan" set monitor otherbss fcsfail
ip link set "$wlan" up
iw dev "$wlan" set freq "$mhz" || iw dev "$wlan" set channel "$ch"
iw dev "$wlan" set txpower fixed "$mbm" || true

echo "wifinjector: iface=$wlan ch=$ch (${mhz} MHz) txp=${txp}dBm"
iw dev "$wlan" info | egrep -i 'type|channel|txpower' || true
./wifinjector "$wlan"
