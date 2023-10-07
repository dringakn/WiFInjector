#!/usr/bin/env python3

from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt
import os
import sys

# Set the wireless interface name (e.g., wlan0) - change this to match your interface
iface = "wlan0"

# Create a function to inject a WiFi packet


def inject_wifi_packet(channel, data_rate):
    # Define the SSID and BSSID (access point MAC address)
    ssid = "MyNetwork"
    bssid = "00:11:22:33:44:55"

    # Construct the WiFi packet
    packet = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                                addr2=bssid, addr3=bssid) / Dot11Beacon(cap="ESS") / \
        Dot11Elt(ID="SSID", info=ssid) / Dot11Elt(ID="Rates",
                                                  info="\x82\x84\x0b\x16") / Dot11Elt(ID="DSset",
                                                                                      info=chr(
                                                                                          channel))

    # Set the channel and data rate
    os.system(f"iwconfig {iface} channel {channel}")
    os.system(f"iwconfig {iface} rate {data_rate}M")

    # Inject the packet
    packet.show()  # Display the packet
    sendp(packet, iface=iface, count=1)


# Set the channel and data rate (adjust these values as needed)
target_channel = 6  # Channel 6 (2.4 GHz)
target_data_rate = 24  # 24 Mbps

# Inject the WiFi packet
inject_wifi_packet(target_channel, target_data_rate)
