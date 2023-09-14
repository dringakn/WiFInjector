# WiFInjector

## Description

WiFInjector is a C program for injecting and monitoring wireless network packets. It utilizes the pcap library for packet capture and injection, making it a versatile tool for various wireless network testing and monitoring tasks. The program supports the display of Radiotap header information, IEEE 802.11 frame details, packet data, and statistics. It can also enable packet transmission.

# Features

    - Packet Capture: WiFInjector captures wireless network packets from a specified network interface.

    - Packet Injection: It allows you to inject custom packets into the wireless network.

    - Radiotap Header: You can choose to display Radiotap header information, which includes details about the wireless transmission.

    - IEEE 802.11 Frame: You can also display IEEE 802.11 frame information for captured packets.

    - Packet Data Display: WiFInjector can display the raw packet data for a better understanding of the packet's contents.

    - Statistics: The program provides statistics about packet transmission and reception rates.

    - Keyboard Shortcuts: Convenient keyboard shortcuts are available to toggle different display options and settings.

## Prerequisites

Before you can use WiFInjector, ensure that you have the following prerequisites installed:

    - Linux Operating System: The program is designed for Linux.

    - C Compiler: You'll need a C compiler (e.g., GCC) to build the program.

    - Libpcap Library: Ensure that the libpcap library is installed on your system. You can usually install it using your distribution's package manager.

## Installation

Clone the repository to your local machine:

```
git clone https://github.com/yourusername/wifinjector.git
```

Navigate to the project directory:

```
cd wifinjector
```

**Compile the program:**

```
make
```

This will generate the wifinjector binary.

```
make clean
```

This will clean the wifinjector binary and other build artifacts.

## Usage

To run WiFInjector, use the following command:

```
./wifinjector [options] <interface>
```

**options** are command-line options that allow you to configure various program settings. **interface** is the name of the network interface you want to use for packet capture and injection.

**Command-Line Options**

    -f, --fcs: Mark packets as having FCS (CRC) already.
    -b, --blocking: Set blocking mode (by default, it's non-blocking).
    -r, --radiotap: Show Radiotap header information.
    -i, --ieee80211: Show IEEE 802.11 frame information.
    -p, --packet: Show packet data.
    -s, --stats: Show statistics.
    -t, --transmit: Enable packet transmission.
    -h, --help: Display the help message.

## Keyboard Shortcuts

While the program is running, you can use keyboard shortcuts to interact with it:

    Press 'r' or 'R' to toggle Radiotap header display.
    Press 'i' or 'I' to toggle IEEE 802.11 frame display.
    Press 'p' or 'P' to toggle packet data display.
    Press 's' or 'S' to toggle statistics display.
    Press 't' or 'T' to toggle packet transmission.
    Press 'j' or 'J' to decrease MTU size.
    Press 'k' or 'K' to increase MTU size.
    Press 'n' or 'N' to decrease data rate.
    Press 'm' or 'M' to increase data rate.
    Press 'q' or 'Q' to quit the program.

## Example Usage

For the ease of use

```
sudo ./test.sh wlxXXXXXXXXXXXX 1 20
```
Thie script shall configure the specified interface (wlxXXXXXXXXXXXX, where XXX denotes the MAC address of the wifi interface) in to monitor mode at channel 1 and the sets the tx power to be 20 dBm.

For manual launch use:

```
sudo ./wifinjector -f -s -t wlan0
```

This command starts WiFInjector with FCS marking enabled, statistics display, and packet transmission on the wlan0 interface.
Functions

WiFInjector provides several functions for configuring and interacting with the wireless network:

    - Packet Capture: The program captures wireless network packets from the specified interface.

    - Packet Injection: It can inject custom packets into the wireless network.

    - Radiotap Header Display: You can choose to display Radiotap header information to gain insights into wireless transmission.

    - IEEE 802.11 Frame Display: The program allows you to display IEEE 802.11 frame information for captured packets.

    - Packet Data Display: WiFInjector can display the raw packet data for better analysis.

    - Statistics: The program provides statistics about packet transmission and reception rates.

    - Keyboard Shortcuts: Convenient keyboard shortcuts are available for quick toggling of display options and settings.

## Contributing

Contributions to WiFInjector are welcome! If you have ideas for improvements or bug fixes, feel free to create issues or pull requests on the GitHub repository.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

WiFInjector makes use of the following libraries and technologies:

    libpcap - The Packet Capture library.
    getopt - For processing command-line options.
    termios - For terminal I/O handling.
    signal - For signal handling.

Special thanks to the authors and maintainers of these open-source projects.

## Authors

    Dr. -Ing. Ahmad Kamal Nasir

## Contact

For questions or inquiries, please contact [dringakn@gmail.com].

Thank you for using WiFInjector! We hope this tool helps you with your wireless network testing and monitoring needs.
