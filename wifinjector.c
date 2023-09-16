#include <getopt.h> // Header for processing command-line options using getopt
#include <linux/wireless.h> // Header for Wireless Extensions, used for wireless networking information
#include <pcap.h> // Header for the pcap library, used for packet capture and injection
#include <signal.h> // Header for signal handling, used for setting up signal handlers
#include <stdlib.h> // Header for standard library functions, such as memory allocation and exit codes
#include <string.h> // Header for string manipulation functions, like strcpy and memcpy
#include <sys/ioctl.h> // Header for ioctl system call, used for low-level device control
#include <termios.h> // Header for terminal I/O handling, used for keyboard input handling
#include <unistd.h> // Header for POSIX system calls, like close() and usleep()

#define MAX_BUFF_SIZE 4096     // Maximum buffer size for packet data
#define MAX_MTU_SIZE 1500      // Maximum MTU (Maximum Transmit Unit) size
#define MAX_TX_POWER 40        // Maximum allowed transmit power in dBm
#define MAX_DELAY 1000         // Maximum delay in milliseconds
#define MAX_CHANNEL 165        // Maximum supported channel number
#define MAX_MAC_BUFF_SIZE 6    // MAC Address array size
#define HOSTNAME_BUFF_SIZE 256 // Hostname buffer
#define OFFSET_FLAGS 16        // Offset for flags in packet data
#define OFFSET_RATE 17         // Offset for data rate in packet data
#define MCS_OFFSET 25          // Offset for MCS rate in packet data
#define MCS_RATE_OFFSET 27     // Offset for MCS rate index in packet data
#define MAX_RATES 12           // Rate array size
#define RADIOTAPFRAME_SIZE 32  // Size of the Radiotap header frame
#define IEEE80211FRAME_SIZE 24 // Size of the IEEE 802.11 frame

// Definition of a union representing Radiotap header
union RadiotapHeader {
  struct {
    // Radiotap header fields
    unsigned char revision; // Revision of the Radiotap header
    unsigned char padding;  // Padding or alignment
    unsigned short length;  // Overall Radiotap header length
    union {
      struct {
        unsigned int tsft : 1;              // Timestamp is present
        unsigned int flags : 1;             // Flags field is present
        unsigned int rate : 1;              // Data Rate is present
        unsigned int channel : 1;           // Channel information is present
        unsigned int fhss : 1;              // FHSS is present
        unsigned int dbm_signal : 1;        // dBm signal strength is present
        unsigned int dbm_noise : 1;         // dBm noise level is present
        unsigned int lock_quality : 1;      // Lock quality is present
        unsigned int tx_attenuation : 1;    // Transmit attenuation is present
        unsigned int db_tx_attenuation : 1; // dB transmit attenuation is pres
        unsigned int dbm_tx_power : 1;      // dBm transmit power is present
        unsigned int antenna : 1;           // Antenna information is present
        unsigned int db_antsignal : 1; // dB antenna signal strength is present
        unsigned int db_antnoise : 1;  // dB antenna noise level is present
        unsigned int rx_flags : 1;     // Receive flags are present
        // unsigned int reserved : 16;    // Reserved bits
      } fields;
      unsigned int data;
    } pFlags1; // First present word

    unsigned int pFlags2; // Second present word
    unsigned int pFlags3; // Third present word
    union {
      struct {
        unsigned char cfp : 1;        // CFP: Contention-Free Period
        unsigned char preamble : 1;   // Short Preamble
        unsigned char wep : 1;        // WEP Encrypted
        unsigned char fragmented : 1; // Fragmentation
        unsigned char fcs : 1;        // FCS at end
        unsigned char data_pad : 1;   // Data padding
        unsigned char bad_fcs : 1;    // Bad FCS
        unsigned char short_gi : 1;   // Short Guard Interval
      } fields;
      unsigned char data;
    } flags;                    // Flags
    unsigned char dataRate;     // Data rate
    unsigned short chFrequency; // Channel frequency
    union {
      struct {
        unsigned short padding : 4;  // padding
        unsigned short turbo : 1;    // Turbo channel
        unsigned short CCK : 1;      // CCK channel
        unsigned short OFDM : 1;     // OFDM channel
        unsigned short band2GHz : 1; // 2 GHz spectrum channel
        unsigned short band5GHz : 1; // 5 GHz spectrum channel
        unsigned short passive : 1; // Passive channel (don't use for FCS check)
        unsigned short dynamicCCKOFDM : 1; // Dynamic channel (CCK-OFDM)
        unsigned short GFSK : 1;           // Gaussian Frequency Shift Keying
        unsigned short GSM : 1;            // Half rate channel
        unsigned short staticTurbo : 1;    // Half rate channel
        unsigned short chWidth10MHz : 1;   // Half rate channel
        unsigned short chWidth5MHz : 1;    // Quarter rate channel
      } fields;
      unsigned short data;
    } chFlags;                    // Channel flags
    char RSSI;                    // Received Signal Strength Indicator (RSSI)
    unsigned short signalQuality; // Signal quality
    unsigned short rxFlags;       // Receiver flags
    char RSSI1;                   // RSSI for antenna 1
    unsigned char antenna1;       // Antenna 1
    char RSSI2;                   // RSSI for antenna 2
    unsigned char antenna2;       // Antenna 2
  } fields;
  unsigned char data[RADIOTAPFRAME_SIZE];
};

// Definition of a union representing IEEE 802.11 frame
union IEEE80211Frame {
  struct {
    union {
      struct {
        unsigned short protocolVersion : 2; // Protocol Version (bits 0-1)
        unsigned short type : 2;            // Type (bits 2-3)
        unsigned short subtype : 4;         // Subtype (bits 4-7)
        unsigned short toDS : 1;            // To DS (bit 8)
        unsigned short fromDS : 1;          // From DS (bit 9)
        unsigned short moreFragments : 1;   // More Fragments (bit 10)
        unsigned short retry : 1;           // Retry (bit 11)
        unsigned short pwrMgmt : 1;         // Power Management (bit 12)
        unsigned short moreData : 1;        // More Data (bit 13)
        unsigned short wep : 1;             // WEP (bit 14)
        unsigned short order : 1;           // Order (bit 15)
      } fields;
      unsigned short data;
    } frameControl;                                 // Frame control
    unsigned short duration;                        // Duration
    unsigned char destAddress[MAX_MAC_BUFF_SIZE];   // Destination MAC address
    unsigned char sourceAddress[MAX_MAC_BUFF_SIZE]; // Source MAC address
    unsigned char bssid[MAX_MAC_BUFF_SIZE]; // Basic Service Set Identifier
    unsigned short sequenceControl;         // Sequence control
  } fields;
  unsigned char data[IEEE80211FRAME_SIZE];
};

typedef struct iwreq IWReq; // Typedef for Wireless Extensions request structure

// Constant for packet size, used in various parts of the program
const unsigned int PACKET_SIZE = RADIOTAPFRAME_SIZE + IEEE80211FRAME_SIZE;

// Various program configuration flags and settings
int flagMarkWithFCS = 0; // Flag to mark packets with FCS (CRC) already
int flagNonBlocking =
    1; // Flag to set non-blocking mode (1: non-blocking, 0: blocking)
int flagShowRadioTap = 0;   // Flag to show Radiotap header information
int flagShowIEEE80211 = 0;  // Flag to show IEEE 802.11 frame information
int flagShowPacket = 0;     // Flag to show packet data
int flagShowStats = 1;      // Flag to show statistics
int flagEnableTransmit = 0; // Flag to enable packet transmission

// Statistics counters for packet transmission and reception
unsigned int totalTXPacket = 0;  // Total transmitted packets per second
unsigned int totalTXBytes = 0;   // Total transmitted bytes per second
unsigned int totalRXPackets = 0; // Total received packets per second
unsigned int totalRXBytes = 0;   // Total received bytes per second

unsigned int totalTXFPacket = 0;  // Total failed transmitted packets per second
unsigned int totalTXFBytes = 0;   // Total failed transmitted bytes per second
unsigned int totalRXFPackets = 0; // Total failed received packets per second
unsigned int totalRXFBytes = 0;   // Total failed received bytes per second

// Delay between packet transmissions in milliseconds
unsigned int delay = 1;

// Selected transmit power in dBm
unsigned int selectedTxPower = MAX_TX_POWER;

// Selected channel number
unsigned int selectedChannel = 1;

// Selected rate index in the array
unsigned int selectedRateIndex = 3;

// Maximum transmit unit (MTU) size
unsigned int selectedMTUSize = MAX_MTU_SIZE;

// Variables for keyboard input handling
unsigned char chars, keyboardBuff[3];

// Buffer to store the host name
char hostNameBuff[HOSTNAME_BUFF_SIZE] = {0x00};

// MAC address of the host device
unsigned char deviceMACAddress[MAX_MAC_BUFF_SIZE] = {0xFF}; // Host MAC
unsigned char destMACAddress[MAX_MAC_BUFF_SIZE] = {0xFF};   // Destination MAC
char rxBuffer[MAX_BUFF_SIZE] = {' '};
char txBuffer[MAX_BUFF_SIZE] = {' '};

const int rates[MAX_RATES] = {1, 2, 5, 6, 9, 11, 12, 18, 24, 36, 48, 54};

/**
 * @brief Convert a Wi-Fi channel number to its corresponding frequency.
 *
 * This function takes a Wi-Fi channel number and calculates the frequency
 * at which the channel operates. It supports both 2.4 GHz and 5 GHz bands.
 *
 * @param channel The Wi-Fi channel number to convert.
 * @return The frequency in MHz corresponding to the given channel.
 *
 * @note Supported channel ranges:
 * - 2.4 GHz band: Channels 1 to 13
 * - 5 GHz band: Channels 36 to 165
 * - Invalid channels or bands will return a default frequency of 2.4 GHz.
 */
int wifiChannelToFrequency(int channel) {
  // Check if the channel is within the 2.4 GHz band range (Channels 1 to 13)
  if (channel >= 1 && channel <= 13) {
    // Calculate the frequency for the 2.4 GHz band using the channel number
    return 2412 + (channel - 1) * 5;
  }
  // Check if the channel is within the 5 GHz band range (Channels 36 to 165)
  else if (channel >= 36 && channel <= 165) {
    // Calculate the frequency for the 5 GHz band using the channel number
    return 5180 + (channel - 36) * 5;
  }
  // Default case: Invalid channel or band, return a default frequency of 2.4
  // GHz
  else {
    return 2412;
  }
}

/**
 * @brief Reads characters from the keyboard input without blocking.
 *
 * This function sets the terminal to raw mode, allowing it to read characters
 * from the standard input (keyboard) without waiting for a newline (Enter key).
 *
 * @param[in,out] kbBuffer An unsigned char array to store the input characters.
 * @return The number of characters read (0 if no character available, EOF if
 * error).
 */
unsigned char getKeyboard(unsigned char kbBuffer[3]) {
  unsigned char chrCounts = 0; // Buffer to input character
  struct termios orig_term_attr;
  struct termios new_term_attr;

  // Get the original terminal attributes
  tcgetattr(STDIN_FILENO, &orig_term_attr);

  // Copy the original attributes to a new structure
  memcpy(&new_term_attr, &orig_term_attr, sizeof(struct termios));

  // Set the terminal to raw mode, disabling ECHO and ICANON (canonical mode)
  new_term_attr.c_lflag &= ~(ECHO | ICANON);

  // Set VTIME (timeout in tenths of a second) and VMIN (minimum number of
  // characters to read)
  new_term_attr.c_cc[VTIME] = 0;
  new_term_attr.c_cc[VMIN] = 0;

  // Apply the new terminal attributes
  tcsetattr(STDIN_FILENO, TCSANOW, &new_term_attr);

  // Read a character from the stdin stream without blocking
  // Returns EOF (-1) if no character is available
  chrCounts = read(STDIN_FILENO, kbBuffer, 3); // Read the character

  // Restore the original terminal attributes
  tcsetattr(STDIN_FILENO, TCSANOW, &orig_term_attr);

  // Return the number of characters read (or EOF if an error occurred)
  return chrCounts;
}

/**
 * @brief Signal handler function for SIGALRM.
 *
 * This function is called when the SIGALRM signal is received, typically
 * from a timer. It performs the following tasks:
 * 1. If flagShowStats is set, it prints statistics related to packet
 *    transmission and reception.
 * 2. Resets counters for transmitted and received packets and bytes.
 * 3. Flushes the standard output stream.
 * 4. Sets a timer for the next SIGALRM signal.
 *
 * @param sig The signal number (SIGALRM in this case).
 */
void sigalrm_handler(int sig) {

  if (flagShowStats) {
    // Calculate success rate (percentage of received packets)
    int successRate = (totalTXBytes) ? totalRXPackets * 100 / totalTXPacket : 0;
    // Print statistics including received and transmitted data
    printf(
        "[%s] RxPacketRate:%03u[%03u] RXBPS:%05u[%05u] TxPacketRate:%03u[%03u] "
        "TXBPS:%05u[%05u] "
        "TX[%01d]NB[%01d]D[%02u]PWR[%02u]CH[%03u]MTU[%04u]RATE[%02d]SUCCESS["
        "%03d]\n",
        hostNameBuff, totalRXPackets, totalRXFPackets, totalRXBytes,
        totalRXFBytes, totalTXPacket, totalTXFPacket, totalTXBytes,
        totalTXFBytes, flagEnableTransmit, flagNonBlocking, delay,
        selectedTxPower, selectedChannel, selectedMTUSize,
        rates[selectedRateIndex], successRate);
  }

  // Reset counters for transmitted and received data
  totalTXBytes = 0;
  totalTXPacket = 0;
  totalRXBytes = 0;
  totalRXPackets = 0;
  totalTXFPacket = 0;
  totalTXFBytes = 0;
  totalRXFPackets = 0;
  totalRXFBytes = 0;

  // Flush the standard output
  fflush(stdout);

  // Set the timer for the next signal
  struct itimerval tout_val;
  tout_val.it_interval.tv_sec = 1; // Interval in seconds
  tout_val.it_interval.tv_usec = 0;
  tout_val.it_value.tv_sec = 1; // Initial delay in seconds
  tout_val.it_value.tv_usec = 0;
  // Set the timer using setitimer to trigger the signal periodically
  setitimer(ITIMER_REAL, &tout_val, 0);
}

/**
 * @brief Display usage information for the wifinjector program.
 *
 * This function prints a usage message to the standard output, explaining
 * how to use the wifinjector program and its command-line options.
 */
void usage(void) {
  printf("Usage: wifinjector [options] <interface>\n\n"
         "Options:\n"
         "  -f, --fcs           Mark as having FCS (CRC) already\n"
         "  -b, --blocking      Set blocking mode, default otherwise "
         "non-blocking\n"
         "  -r, --radiotap      Show Radiotap header\n"
         "  -i, --ieee80211     Show IEEE802.11 frame\n"
         "  -p, --packet        Show packet data\n"
         "  -s, --stats         Show statistics\n"
         "  -t, --transmit      Enable packet transmission\n"
         "  -h, --help          Display this help message\n\n"
         "Keyboard Shortcuts:\n"
         "  - Press 'r' or 'R' to toggle Radiotap header display\n"
         "  - Press 'i' or 'I' to toggle IEEE802.11 frame display\n"
         "  - Press 'p' or 'P' to toggle packet data display\n"
         "  - Press 's' or 'S' to toggle statistics display\n"
         "  - Press 't' or 'T' to toggle packet transmission\n"
         "  - Press 'j' or 'J' to decrease MTU size\n"
         "  - Press 'k' or 'K' to increase MTU size\n"
         "  - Press 'n' or 'N' to decrease data rate\n"
         "  - Press 'm' or 'M' to increase data rate\n"
         "  - Press 'q' or 'Q' to quit the program\n\n");
  // Exit the program with a non-zero status code to indicate an error.
  exit(1);
}

/**
 * @brief Prints information from a Radiotap header structure.
 *
 * This function takes a Radiotap header as input and prints various fields
 * from it in a formatted manner.
 *
 * @param header A pointer to a union RadiotapHeader structure.
 */
void printRadiotapHeader(const union RadiotapHeader *header) {
  printf("V:%02X P:%02X L:%04X[%04u] P1:%08X P2:%08X P3:%08X FLGS:%02X DR:%03u "
         "FREQ:%04u CHFLG:%04X RSSI:%04d Q:%03d RXFLG:%04X RSSI1:%03d "
         "ANT1:%01d RSSI2:%04d ANT2:%01d\n",
         // Display Radiotap header fields in the specified order
         header->fields.revision,     // Version
         header->fields.padding,      // Padding
         header->fields.length,       // Length
         header->fields.length,       // Length (repeated for clarity)
         header->fields.pFlags1.data, // Flags part 1
         header->fields.pFlags2,      // Flags part 2
         header->fields.pFlags3,      // Flags part 3
         header->fields.flags.data,   // General flags
         header->fields.dataRate,     // Data rate
         header->fields.chFrequency,  // Channel frequency
         header->fields.chFlags.data, // Channel flags
         header->fields.RSSI, // Received Signal Strength Indicator (RSSI)
         header->fields.signalQuality, // Signal quality
         header->fields.rxFlags,       // Receive flags
         header->fields.RSSI1,         // RSSI of antenna 1
         header->fields.antenna1,      // Antenna 1
         header->fields.RSSI2,         // RSSI of antenna 2
         header->fields.antenna2       // Antenna 2
  );
}

/**
 * @brief Print information about an IEEE 802.11 frame.
 *
 * This function takes an IEEE 802.11 frame structure and prints its various
 * fields.
 *
 * @param frame Pointer to the IEEE80211Frame structure to be printed.
 */
void printIEEE80211Frame(const union IEEE80211Frame *frame) {
  printf("FC:0x%04X DUR:0x%04X DEST:"
         "%02X:%02X:%02X:%02X:%02X:%02X SRC:%02X:%02X:%02X:%02X:%02X:%02X "
         "BSSID:%02X:%02X:%02X:%02X:%02X:%02X SEQCTRL:0x%04X\n",
         frame->fields.frameControl.data, frame->fields.duration,
         frame->fields.destAddress[0], frame->fields.destAddress[1],
         frame->fields.destAddress[2], frame->fields.destAddress[3],
         frame->fields.destAddress[4], frame->fields.destAddress[5],
         frame->fields.sourceAddress[0], frame->fields.sourceAddress[1],
         frame->fields.sourceAddress[2], frame->fields.sourceAddress[3],
         frame->fields.sourceAddress[4], frame->fields.sourceAddress[5],
         frame->fields.bssid[0], frame->fields.bssid[1], frame->fields.bssid[2],
         frame->fields.bssid[3], frame->fields.bssid[4], frame->fields.bssid[5],
         frame->fields.sequenceControl);
}

/**
 * @brief Dump packet data to the console.
 *
 * This function prints the packet data as a sequence of characters, replacing
 * non-printable characters with dots for readability.
 *
 * @param ptr Pointer to the start of the packet data.
 * @param nLength Length of the packet data to be printed.
 */
void dumpPacketData(const char *ptr, int nLength) {
  // Print the length of the packet data in a fixed-width format.
  printf("[%08d]: ", nLength);

  // Loop through each character in the packet data.
  for (size_t i = 0; i < nLength; i++) {
    char currentChar = ptr[i];

    // Check if the current character is a printable character (ASCII 32 to
    // 126).
    if (currentChar >= 32 && currentChar <= 126) {
      // Printable character, so print it as is.
      printf("%c", currentChar);
    } else {
      // Non-printable character, so print a dot for readability.
      printf(".");
    }
  }

  // Print a newline character to separate this line from the next.
  printf("\n");
}

/**
 * @brief Inject a custom packet into a network interface.
 *
 * This function constructs a packet by combining a Radiotap header, an IEEE
 * 802.11 frame, and additional information, and injects it into the specified
 * network interface using pcap.
 *
 * @param pcap A pointer to the pcap handle for the network interface.
 * @param rt A pointer to a union containing Radiotap header data.
 * @param frame A pointer to a union containing IEEE 802.11 frame data.
 * @return 0 on success, -1 on failure.
 */
int injectPacket(pcap_t *pcap, union RadiotapHeader *rt,
                 union IEEE80211Frame *frame) {
  int len = 0;

  // Copy Radiotap header data to the packet
  // rt->fields.flags.fields.fcs = 1;
  memcpy(txBuffer + len, rt->data, RADIOTAPFRAME_SIZE);
  len += RADIOTAPFRAME_SIZE;

  // Copy IEEE 802.11 frame data to the packet
  memcpy(txBuffer + len, frame->data, IEEE80211FRAME_SIZE);
  len += IEEE80211FRAME_SIZE;

  // Copy additional information to the packet
  int len1 = sprintf(txBuffer + len, "TXPacket#%06u Host:%s ", totalTXPacket,
                     hostNameBuff);
  len += len1;

  // Inject the packet into the network interface using pcap
  int sentBytes = pcap_inject(pcap, txBuffer, len);

  if (sentBytes != len) {
    totalTXFPacket++;
    totalTXFBytes += sentBytes;
    // perror("Trouble injecting packet");
    return -1; // Injection failed
  } else {
    // Update statistics on successful injection
    totalTXPacket++;
    totalTXBytes += sentBytes;
    return 0; // Injection successful
  }
}

/**
 * @brief Retrieves and prints the hostname of the local machine.
 *
 * This function retrieves the hostname of the local machine using the
 * `gethostname` function and prints it to the standard output. If an error
 * occurs during the hostname retrieval, it displays an error message using
 * `perror`.
 */
void getHostname() {
  // Attempt to retrieve the hostname
  if (gethostname(hostNameBuff, sizeof(hostNameBuff) - 1)) {
    // If an error occurs, print an error message
    perror("unable to get hostname");
  } else {
    // Print the retrieved hostname to the standard output
    printf("Hostname: %s\n", hostNameBuff);
  }
  // Null-terminate the hostname string to ensure it is properly formatted
  hostNameBuff[sizeof(hostNameBuff) - 1] = '\0';
}

/**
 * @brief Sends an IOCTL command to a socket with the provided configuration
 * command and IOCTL request structure.
 *
 * This function creates a socket, sends an IOCTL command with the given
 * configuration command and IOCTL request structure, and then closes the
 * socket.
 *
 * @param configCommand The IOCTL command to be sent.
 * @param wrq A pointer to the IOCTL request structure containing the
 * configuration data.
 * @return 0 on success, -1 on socket error, 1 on IOCTL error.
 */
int sendIOCTLCommand(int configCommand, IWReq *wrq) {
  int result = 0; // Initialize the result to indicate no error
  int sock = socket(AF_INET, SOCK_DGRAM,
                    0); // Create a socket for sending IOCTL commands
  if (sock == -1) {     // Check for socket creation error
    perror("Socket Error");
    result = -1; // Set the result to indicate a socket error
  } else {
    if (ioctl(sock, configCommand, wrq) == -1) { // Send the IOCTL command
      perror("IOCTLCommand Error");
      result = 1; // Set the result to indicate an IOCTL error
    }
    close(sock); // Close the socket
  }
  return result; // Return the result code
}

/**
 * @brief Get the MAC address of a network interface.
 *
 * This function retrieves the MAC address (hardware address) of a specified
 * network interface.
 *
 * @param[in] ifaceName The name of the network interface for which to retrieve
 * the MAC address.
 * @return 0 if the MAC address is successfully retrieved, -1 on failure.
 */
int getMACAddress(const char *ifaceName) {
  int result = 0;

  // Create a struct to hold IOCTL request information
  struct iwreq wrq;

  // Initialize the wrq struct to all zeros
  memset(&wrq, 0, sizeof(struct iwreq));

  // Copy the network interface name into the wrq struct
  strncpy(wrq.ifr_name, ifaceName, IFNAMSIZ);

  // Send an IOCTL command to retrieve the hardware (MAC) address of the
  // interface
  if (sendIOCTLCommand(SIOCGIFHWADDR, &wrq) == 0) {
    // Copy the MAC address into the deviceMACAddress array
    memcpy(deviceMACAddress, wrq.u.addr.sa_data, MAX_MAC_BUFF_SIZE);

    // Print the retrieved MAC address in hexadecimal format
    printf("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n", deviceMACAddress[0],
           deviceMACAddress[1], deviceMACAddress[2], deviceMACAddress[3],
           deviceMACAddress[4], deviceMACAddress[5]);
  } else {
    // If the IOCTL command fails, set the result to -1
    result = -1;
  }

  // Return the result (0 for success, -1 for failure)
  return result;
}

/**
 * @brief Set the transmit power for a wireless network interface.
 *
 * This function sets the transmit power for the specified wireless network
 * interface to the desired value in dBm.
 *
 * @param[in] ifaceName The name of the wireless network interface.
 * @param[in] txPower The desired transmit power in dBm.
 *
 * @return 0 on success, -1 on failure.
 */
int setTXPower(const char *ifaceName, unsigned char txPower) {
  int result = 0; // Initialize the result variable to 0 (success).
  IWReq wrq;      // Create a struct to hold the IOCTL request parameters.

  // Clear the memory of the wrq struct to ensure it's empty.
  memset(&wrq, 0, sizeof(struct iwreq));

  // Copy the name of the wireless interface into the IOCTL request struct.
  strncpy(wrq.ifr_name, ifaceName, IFNAMSIZ);

  // To Set Power, first load previous parameters by getting previous values
  // Check if sending an IOCTL command to get the previous TX power value is
  // successful.
  if (sendIOCTLCommand(SIOCGIWTXPOW, &wrq) == 0) {
    // Print the previous TX power and its "fixed" status.
    printf("Transmit power: %d[%d]\n", wrq.u.txpower.value,
           wrq.u.txpower.fixed);

    // Set the desired TX power in dBm.
    wrq.u.txpower.value = txPower;

    // Indicate that the TX power is fixed (not automatically adjusted).
    wrq.u.txpower.fixed = 1;

    // Check if sending an IOCTL command to set the new TX power is successful.
    if (sendIOCTLCommand(SIOCSIWTXPOW, &wrq) == 0) {
      // Success: do nothing.
    } else {
      // Error: Set the result variable to -1.
      result = -1;
    }
  } else {
    // Error: Set the result variable to -1.
    result = -1;
  }

  // Return the result of the operation (0 for success, -1 for failure).
  return result;
}

/**
 * @brief Set the wireless network interface to monitor mode.
 *
 * This function sets the specified wireless network interface to monitor mode,
 * which allows it to capture wireless packets. It uses IOCTL commands to change
 * the interface mode.
 *
 * @param ifaceName The name of the network interface to set to monitor mode.
 * @return 0 if the mode is successfully set to monitor mode, -1 otherwise.
 */
int setMonitorMode(const char *ifaceName) {
  int result = 0; // Initialize the result variable to success (0).
  IWReq wrq;      // Create a structure for IOCTL requests.

  // Clear the memory of the wrq structure to avoid garbage values.
  memset(&wrq, 0, sizeof(struct iwreq));

  // Copy the provided interface name into the wrq structure.
  strncpy(wrq.ifr_name, ifaceName, IFNAMSIZ);

  // Check the current mode of the wireless interface using an IOCTL command.
  if (sendIOCTLCommand(SIOCGIWMODE, &wrq) == 0) {
    printf("MODE: %d\n", wrq.u.mode); // Print the current mode.

    // Set the mode to 6, which corresponds to "monitor" mode.
    wrq.u.mode = 6; /* 0=Auto, 1=Adhoc, 2=Infra, 3=master, 4=repeater,5=second,
                       6=monitor, 7=mesh */

    // Use an IOCTL command to set the interface mode to "monitor" mode.
    if (sendIOCTLCommand(SIOCSIWMODE, &wrq) == 0) {
      // Mode change was successful, do nothing.
    } else {
      // Failed to set the mode, update the result variable to indicate an
      // error.
      result = -1;
    }
  } else {
    // Failed to retrieve the current mode, update the result variable to
    // indicate an error.
    result = -1;
  }

  return result; // Return the result code.
}

/**
 * @brief Set the frequency of a wireless network interface to a specified
 * channel.
 *
 * This function sets the frequency of a wireless network interface to the
 * specified channel by using IOCTL commands. It first checks if the current
 * mode is in monitor mode or if the interface is in use for a connection.
 *
 * @param[in] ifaceName The name of the wireless network interface.
 * @param[in] channel The channel number to set.
 * @return 0 on success, -1 on failure.
 */
int setFrequency(const char *ifaceName, unsigned char channel) {
  int result = 0; // Initialize the result variable to indicate success.
  IWReq wrq;      // Create a structure for IOCTL requests.

  // Clear the memory of the wrq structure to ensure no garbage data is present.
  memset(&wrq, 0, sizeof(struct iwreq));

  // Copy the interface name (ifaceName) into the wrq structure.
  strncpy(wrq.ifr_name, ifaceName, IFNAMSIZ);

  // Check if the current mode is in monitor mode or if the interface is in use.
  if (sendIOCTLCommand(SIOCGIWFREQ, &wrq) == 0) {
    // Print the current channel frequency.
    printf("Channel Frequency: %d\n", wrq.u.freq.m);

    // Convert the channel number to a frequency and set it in the wrq
    // structure.
    wrq.u.freq.m = wifiChannelToFrequency(channel);

    // Set the new frequency using an IOCTL command.
    if (sendIOCTLCommand(SIOCSIWFREQ, &wrq) == 0) {
      // Frequency setting was successful, do nothing.
    } else {
      // Failed to set the new frequency, set the result to indicate failure.
      result = -1;
    }
  } else {
    // Failed to retrieve the current frequency or mode, set the result to
    // indicate failure.
    result = -1;
  }

  return result; // Return the result code (0 for success, -1 for failure).
}

/**
 * @brief Set the Maximum Transmission Unit (MTU) size for a given network
 * interface.
 *
 * This function sets the MTU size for a specified network interface using IOCTL
 * commands.
 *
 * @param ifaceName The name of the network interface.
 * @param mtuBytes The desired MTU size in bytes to set for the network
 * interface.
 * @return 0 if the MTU is set successfully, -1 if there is an error.
 */
int setMTU(const char *ifaceName, unsigned short mtuBytes) {
  int result = 0; // Initialize the result variable to 0 (indicating success).
  IWReq wrq;      // Declare a structure to hold IOCTL requests.

  // Initialize the wrq structure with zeros to ensure no leftover data.
  memset(&wrq, 0, sizeof(struct iwreq));

  // Copy the network interface name (ifaceName) to the wrq structure.
  strncpy(wrq.ifr_name, ifaceName, IFNAMSIZ);

  // Check the current MTU size of the network interface and print it.
  if (sendIOCTLCommand(SIOCGIFMTU, &wrq) == 0) {
    printf("MTU size: %d bytes\n", wrq.u.param.value);

    // Set the desired MTU size in the wrq structure.
    wrq.u.param.value = mtuBytes;

    // Apply the new MTU size to the network interface using an IOCTL command.
    if (sendIOCTLCommand(SIOCSIFMTU, &wrq) == 0) {
      // MTU is set successfully; no additional action needed.
    } else {
      // Failed to set the MTU size; update the result variable to indicate an
      // error.
      result = -1;
    }
  } else {
    // Failed to retrieve the current MTU size; update the result variable to
    // indicate an error.
    result = -1;
  }

  // Return the result status: 0 for success, -1 for an error.
  return result;
}

/**
 * @brief Main function for the Wi-Fi Packet Injector program.
 *
 * This function handles command-line arguments, initializes various settings,
 * and continuously captures and manipulates Wi-Fi packets.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @return 0 on success, non-zero on failure.
 */
int main(int argc, char *argv[]) {

  int opt;
  static struct option long_options[] = {{"fcs", no_argument, NULL, 'f'},
                                         {"blocking", no_argument, NULL, 'b'},
                                         {"radiotap", no_argument, NULL, 'r'},
                                         {"ieee80211", no_argument, NULL, 'i'},
                                         {"packet", no_argument, NULL, 'p'},
                                         {"stats", no_argument, NULL, 's'},
                                         {"transmit", no_argument, NULL, 't'},
                                         {"help", no_argument, NULL, 'h'},
                                         {0, 0, 0, 0}};

  // Parse command-line options using getopt_long
  while ((opt = getopt_long(argc, argv, "fbripsth", long_options, NULL)) !=
         -1) {
    switch (opt) {
    case 'b':
      flagNonBlocking = 0; // Disable non-blocking mode
      break;
    case 'f':
      flagMarkWithFCS = 1; // Enable marking packets with FCS
      break;
    case 'r':
      flagShowRadioTap = 1; // Enable display of Radiotap headers
      break;
    case 'i':
      flagShowIEEE80211 = 1; // Enable display of IEEE 802.11 frames
      break;
    case 'p':
      flagShowPacket = 1; // Enable display of packet data
      break;
    case 's':
      flagShowStats = 1; // Enable display of statistics
      break;
    case 't':
      flagEnableTransmit = 1; // Enable packet transmission
      break;
    case '?':
      break;
    case 'h':
      usage(); // Display usage information
      exit(EXIT_SUCCESS);
    default:
      usage(); // Display usage information and exit with failure
      exit(EXIT_FAILURE);
    }
  }

  // Get hostname and configure network interface
  getHostname();
  if (getMACAddress(argv[optind]) != 0) {
    exit(EXIT_FAILURE);
  }
  if (setTXPower(argv[optind], selectedTxPower) != 0) {
    printf("Unable to set TxPower.\n");
  }
  if (setMonitorMode(argv[optind]) != 0) {
    printf("Unable to set Monitor mode.\n");
  }
  if (setFrequency(argv[optind], selectedChannel) != 0) {
    printf("Unable to set Frequency.\n");
  }
  if (setMTU(argv[optind], selectedMTUSize) != 0) {
    printf("Unable to set MTU.\n");
  }

  // Initialize Radiotap header structure
  union RadiotapHeader rt;
  rt.fields.revision = 0;
  rt.fields.padding = 0;
  rt.fields.length = RADIOTAPFRAME_SIZE;
  rt.fields.pFlags1.data = 0xA00040AE;
  rt.fields.pFlags2 = 0xA0000820;
  rt.fields.pFlags3 = 0x00000820;
  rt.fields.flags.data = 0x10;
  rt.fields.dataRate = rates[selectedRateIndex];
  rt.fields.chFrequency = wifiChannelToFrequency(selectedChannel);
  rt.fields.chFlags.data = 0x00A0;
  rt.fields.RSSI = rt.fields.RSSI1 = rt.fields.RSSI2 = -16;
  rt.fields.signalQuality = 100;
  rt.fields.rxFlags = 0x0000;
  rt.fields.antenna1 = 0;
  rt.fields.antenna2 = 1;
  printRadiotapHeader(&rt);

  // Initialize IEEE 802.11 frame structure
  union IEEE80211Frame frame;
  frame.fields.frameControl.data = 0x0800;
  frame.fields.duration = 0x013A;
  memcpy(frame.fields.destAddress, destMACAddress, MAX_MAC_BUFF_SIZE);
  memcpy(frame.fields.sourceAddress, deviceMACAddress, MAX_MAC_BUFF_SIZE);
  memcpy(frame.fields.bssid, deviceMACAddress, MAX_MAC_BUFF_SIZE);
  frame.fields.sequenceControl = 0xB4CA;
  printIEEE80211Frame(&frame);

  // Set up the timer for the first time
  struct itimerval tout_val;
  tout_val.it_interval.tv_sec = 1; // Interval in seconds
  tout_val.it_interval.tv_usec = 0;
  tout_val.it_value.tv_sec = 1; // Initial delay in seconds
  tout_val.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &tout_val, 0);
  signal(SIGALRM, sigalrm_handler);

  // Open a live capture session with pcap
  char errbuf[PCAP_ERRBUF_SIZE];
  strcpy(errbuf, "");
  pcap_t *pcap = NULL;

  /* filter expression example: ether host 00:E0:2D:5B:40:7D */
  char filter_exp[] = "";
  struct bpf_program fp; /* compiled filter program (expression) */
  bpf_u_int32 mask;      /* subnet mask */
  bpf_u_int32 net;       /* ip */

  /* get network number and mask associated with capture device */
  if (pcap_lookupnet(argv[optind], &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", argv[optind],
            errbuf);
    net = 0;
    mask = 0;
  }

  pcap = pcap_open_live(argv[optind], MAX_BUFF_SIZE, 1, 1, errbuf);
  if (pcap == NULL) {
    printf("Unable to open interface %s in pcap: %s\n", argv[optind], errbuf);
    return 1;
  } else {
    switch (pcap_datalink(pcap)) {
    case DLT_IEEE802_11_RADIO:
      /* 802.11 plus radiotap radio header */
      printf("Link-layer type: DLT_IEEE802_11_RADIO.\n");
      break;
    default:
      printf("Unable to determine pcap link-layer type.\n");
      return 2;
    }
  }

  // Set pcap non-blocking mode
  if (pcap_setnonblock(pcap, flagNonBlocking, errbuf) != 0) {
    printf("Unable to set pcap [non]blocking mode: %s\n", errbuf);
    return 3;
  }

  /* compile the filter expression */
  if (pcap_compile(pcap, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
            pcap_geterr(pcap));
    exit(EXIT_FAILURE);
  }

  /* apply the compiled filter */
  if (pcap_setfilter(pcap, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp,
            pcap_geterr(pcap));
    exit(EXIT_FAILURE);
  }

  // Main packet capture and manipulation loop
  struct pcap_pkthdr *pktMetadata = NULL;
  char *packet = rxBuffer;
  union RadiotapHeader *rt1;
  union IEEE80211Frame *frame1;

  char stopProgram = 0;
  int rxbytes;

  do {
    chars = getKeyboard(keyboardBuff);
    if (chars == 1) /* Standard character */ {
      // Standard character handling (toggle flags, adjust settings, etc.)
      switch (keyboardBuff[0]) {
      case 'r':
      case 'R':
        flagShowRadioTap = (flagShowRadioTap) ? 0 : 1;
        break;
      case 'i':
      case 'I':
        flagShowIEEE80211 = (flagShowIEEE80211) ? 0 : 1;
        break;
      case 'p':
      case 'P':
        flagShowPacket = (flagShowPacket) ? 0 : 1;
        break;
      case 's':
      case 'S':
        flagShowStats = (flagShowStats) ? 0 : 1;
        break;
      case 't':
      case 'T':
        flagEnableTransmit = (flagEnableTransmit) ? 0 : 1;
        break;
      case 'j':
      case 'J':
        if (selectedMTUSize > (2 * PACKET_SIZE + 4)) {
          --selectedMTUSize;
          setMTU(argv[optind], selectedMTUSize);
        }
        break;
      case 'k':
      case 'K':
        if (selectedMTUSize < MAX_MTU_SIZE) {
          ++selectedMTUSize;
          setMTU(argv[optind], selectedMTUSize);
        }
        break;
      case 'n':
      case 'N':
        if (selectedRateIndex > 0) {
          --selectedRateIndex;
          rt.fields.dataRate = rates[selectedRateIndex];
        }
        break;
      case 'm':
      case 'M':
        if (selectedRateIndex < MAX_RATES - 1) {
          ++selectedRateIndex;
          rt.fields.dataRate = rates[selectedRateIndex];
        }
        break;
      case 'q':
      case 'Q':
        stopProgram = 1;
        break;
      default:
        break;
      }
    } else if (chars == 3) /* Special character*/ {
      // Special character handling (e.g., arrow keys)
      if (keyboardBuff[0] == 27 && keyboardBuff[1] == 91) {
        switch (keyboardBuff[2]) {
        case 65: /* UP */
          if (selectedTxPower < MAX_TX_POWER) {
            ++selectedTxPower;
            setTXPower(argv[optind], selectedTxPower);
          }
          break;
        case 66: /* DOWN */
          if (selectedTxPower > 0) {
            --selectedTxPower;
            // setTXPower(argv[optind], selectedTxPower);
            setTXPower(argv[optind], selectedTxPower);
          }
          break;
        case 67: /* RIGHT */
          if (selectedChannel == 13)
            selectedChannel = 36;
          if (selectedChannel < MAX_CHANNEL) {
            ++selectedChannel;
            setFrequency(argv[optind], selectedChannel);
          }
          break;
        case 68: /* LEFT */
          if (selectedChannel == 36)
            selectedChannel = 13;
          else if (selectedChannel > 1) {
            --selectedChannel;
            setFrequency(argv[optind], selectedChannel);
          }
          break;
        case 53: /* PAGE-UP */
          if (delay < MAX_DELAY)
            delay++;
          printf("Delay[mSec]: %d\n", delay);
          break;
        case 54: /* PAGE-DOWN */
          if (delay > 0)
            delay--;
          printf("Delay[mSec]: %d\n", delay);
          break;
        default:
          printf("%d\t%d\t%d\n", (int)keyboardBuff[0], (int)keyboardBuff[1],
                 (int)keyboardBuff[2]);
          break;
        }
      }
    }

    int readPacketStatus =
        pcap_next_ex(pcap, &pktMetadata, (const unsigned char **)&packet);
    int capturedBytes = pktMetadata->caplen;

    if (capturedBytes) {
      switch (readPacketStatus) {
      case 0:
        // packets are being read from a live capture and the packet buffer
        // time-out expired, useful in non-blocking mode!!!
        totalRXFPackets++;
        totalRXFBytes += capturedBytes;

        if (pktMetadata->len != pktMetadata->caplen)
          dumpPacketData(packet, capturedBytes);

        break;

      case 1:
        // the packet was read without problems
        totalRXPackets++;
        totalRXBytes += capturedBytes;

        if (capturedBytes >= PACKET_SIZE) {
          rt1 = (union RadiotapHeader *)(packet);
          frame1 = (union IEEE80211Frame *)(packet + RADIOTAPFRAME_SIZE);

          if (flagShowRadioTap) {
            printRadiotapHeader(rt1);
          }
          if (flagShowIEEE80211) {
            printIEEE80211Frame(frame1);
          }

          rxbytes = capturedBytes - PACKET_SIZE;
          if (flagShowPacket) {
            dumpPacketData(packet + PACKET_SIZE, rxbytes);
          }
        }

        break;

      default:
        // Packet reading error
        if (readPacketStatus < 0) {
        }
      }
    }

    // Inject a packet if enabled
    if (flagEnableTransmit) {
      if (injectPacket(pcap, &rt, &frame) < 0) {
      }
    }

    pktMetadata->len = pktMetadata->caplen = 0;
    usleep(delay * 1000); // Sleep for a specified delay

  } while (!stopProgram);

  // Cleanup and close pcap
  if (pcap != NULL) {
    pcap_close(pcap);
  }

  return 0;
}
