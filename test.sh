#!/bin/bash

# Check if an interface argument is provided, otherwise use "wlxXXXXXXXXXXXX" as default
if [ -n "$1" ]; then
	wlan="$1"
else
	wlan="wlx00c0cab28652"
fi

# Check if an channel argument is provided, otherwise use "1" as default
if [ -n "$2" ]; then
	channel="$2"
else
	channel=1
fi

# Check if an txpower argument is provided, otherwise use "20" as default
if [ -n "$3" ]; then
	txpower="$3"
else
	txpower=20
fi

# Disable the interface and set it to monitor mode
ifconfig "${wlan}" down
iw dev "${wlan}" set monitor otherbss fcsfail # Set the interface to monitor mode with specific options
ifconfig "${wlan}" up
iw dev "${wlan}" set channel "${channel}"
iwconfig "${wlan}" txpower "${txpower}"

# Display a message indicating that the operation is being performed on the chosen interface
echo "Running wifinjector on ${wlan} at channel ${channel} txpower ${txpower} dBm"
./wifinjector "${wlan}"
