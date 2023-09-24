#!/usr/bin/env python3

import pyshark

# Define the interface in monitor mode
interface = "wlx488f4cffe3f2" #"wlx488f4cffd51b"

# Create a packet capture object
capture = pyshark.LiveCapture(interface=interface, display_filter="wlan")

# Start capturing packets
print(f"Capturing WiFi packets on {interface} (Ctrl+C to stop)...")

for packet in capture.sniff_continuously():
    try:
        # Check if the packet has a Radiotap layer
        if "radiotap" in packet:
            radiotap = packet["radiotap"]

            print(f"{radiotap}")

            # Display Radiotap header fields
            # print(f"Radiotap Header Fields:")
            # for field in radiotap.field_names:
            #     print(f"{field}: {radiotap[field]}")

        # Additional processing or analysis can be added here
        print("\n" + "-" * 80 + "\n")

    except Exception as e:
        # Ignore packets that don't have a Radiotap header
        pass
