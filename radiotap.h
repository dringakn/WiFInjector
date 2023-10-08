#ifndef __RADIOTAP_H
#define __RADIOTAP_H

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h> //printf()

#define le16_to_cpu le16toh
#define le32_to_cpu le32toh
#define get_unaligned(p)                                                       \
  ({                                                                           \
    struct packed_dummy_struct {                                               \
      typeof(*(p)) __val;                                                      \
    } __attribute__((packed)) *__ptr = (void *)(p);                            \
                                                                               \
    __ptr->__val;                                                              \
  })
#define get_unaligned_le16(p) le16_to_cpu(get_unaligned((uint16_t *)(p)))
#define get_unaligned_le32(p) le32_to_cpu(get_unaligned((uint32_t *)(p)))

struct radiotap_override {
  uint8_t field;
  uint8_t align : 4, size : 4;
};

struct radiotap_align_size {
  uint8_t align : 4, size : 4;
};

struct ieee80211_radiotap_namespace {
  const struct radiotap_align_size *align_size;
  int n_bits;
  uint32_t oui;
  uint8_t subns;
};

struct ieee80211_radiotap_vendor_namespaces {
  const struct ieee80211_radiotap_namespace *ns;
  int n_ns;
};

/**
 * struct ieee80211_radiotap_iterator - tracks walk thru present radiotap args
 * @this_arg_index: index of current arg, valid after each successful call
 *	to ieee80211_radiotap_iterator_next()
 * @this_arg: pointer to current radiotap arg; it is valid after each
 *	call to ieee80211_radiotap_iterator_next() but also after
 *	ieee80211_radiotap_iterator_init() where it will point to
 *	the beginning of the actual data portion
 * @this_arg_size: length of the current arg, for convenience
 * @current_namespace: pointer to the current namespace definition
 *	(or internally %NULL if the current namespace is unknown)
 * @is_radiotap_ns: indicates whether the current namespace is the default
 *	radiotap namespace or not
 *
 * @overrides: override standard radiotap fields
 * @n_overrides: number of overrides
 *
 * @_rtheader: pointer to the radiotap header we are walking through
 * @_max_length: length of radiotap header in cpu byte ordering
 * @_arg_index: next argument index
 * @_arg: next argument pointer
 * @_next_bitmap: internal pointer to next present u32
 * @_bitmap_shifter: internal shifter for curr u32 bitmap, b0 set == arg present
 * @_vns: vendor namespace definitions
 * @_next_ns_data: beginning of the next namespace's data
 * @_reset_on_ext: internal; reset the arg index to 0 when going to the
 *	next bitmap word
 *
 * Describes the radiotap parser state. Fields prefixed with an underscore
 * must not be used by users of the parser, only by the parser internally.
 */

struct ieee80211_radiotap_iterator {
  struct ieee80211_radiotap_header *_rtheader;
  const struct ieee80211_radiotap_vendor_namespaces *_vns;
  const struct ieee80211_radiotap_namespace *current_namespace;

  unsigned char *_arg, *_next_ns_data;
  uint32_t *_next_bitmap;

  /* Only for RADIOTAP_SUPPORT_OVERRIDES */
  const struct radiotap_override *overrides;
  int n_overrides;

  unsigned char *this_arg;
  int this_arg_index;
  int this_arg_size;

  int is_radiotap_ns;
  int _max_length;
  int _arg_index;
  uint32_t _bitmap_shifter;
  int _reset_on_ext;
};

#ifdef __cplusplus
#define CALLING_CONVENTION "C"
#else
#define CALLING_CONVENTION
#endif

extern CALLING_CONVENTION int ieee80211_radiotap_iterator_init(
    struct ieee80211_radiotap_iterator *iterator,
    struct ieee80211_radiotap_header *radiotap_header, int max_length,
    const struct ieee80211_radiotap_vendor_namespaces *vns);

extern CALLING_CONVENTION int
ieee80211_radiotap_iterator_next(struct ieee80211_radiotap_iterator *iterator);

/**
 * struct ieee82011_radiotap_header - base radiotap header
 */
struct ieee80211_radiotap_header {
  /**
   * @it_version: radiotap version, always 0
   */
  uint8_t it_version;

  /**
   * @it_pad: padding (or alignment)
   */
  uint8_t it_pad;

  /**
   * @it_len: overall radiotap header length
   */
  uint16_t it_len;

  /**
   * @it_present: (first) present word
   */
  uint32_t it_present;
} __attribute__((__packed__));

/* version is always 0 */
#define PKTHDR_RADIOTAP_VERSION 0
#define SET_PRESENT_FLAG(x,flag) ((x)|(1<<flag))

/* see the radiotap website for the descriptions */
enum ieee80211_radiotap_presence {
  IEEE80211_RADIOTAP_TSFT = 0,
  IEEE80211_RADIOTAP_FLAGS = 1,
  IEEE80211_RADIOTAP_RATE = 2,
  IEEE80211_RADIOTAP_CHANNEL = 3,
  IEEE80211_RADIOTAP_FHSS = 4,
  IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
  IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
  IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
  IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
  IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
  IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
  IEEE80211_RADIOTAP_ANTENNA = 11,
  IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
  IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
  IEEE80211_RADIOTAP_RX_FLAGS = 14,
  IEEE80211_RADIOTAP_TX_FLAGS = 15,
  IEEE80211_RADIOTAP_RTS_RETRIES = 16,
  IEEE80211_RADIOTAP_DATA_RETRIES = 17,
  /* 18 is XChannel, but it's not defined yet */
  IEEE80211_RADIOTAP_MCS = 19,
  IEEE80211_RADIOTAP_AMPDU_STATUS = 20,
  IEEE80211_RADIOTAP_VHT = 21,
  IEEE80211_RADIOTAP_TIMESTAMP = 22,

  /* valid in every it_present bitmap, even vendor namespaces */
  IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE = 29,
  IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,
  IEEE80211_RADIOTAP_EXT = 31
};

/* for IEEE80211_RADIOTAP_FLAGS */
enum ieee80211_radiotap_flags {
  IEEE80211_RADIOTAP_F_CFP = 0x01,
  IEEE80211_RADIOTAP_F_SHORTPRE = 0x02,
  IEEE80211_RADIOTAP_F_WEP = 0x04,
  IEEE80211_RADIOTAP_F_FRAG = 0x08,
  IEEE80211_RADIOTAP_F_FCS = 0x10,
  IEEE80211_RADIOTAP_F_DATAPAD = 0x20,
  IEEE80211_RADIOTAP_F_BADFCS = 0x40,
};

/* for IEEE80211_RADIOTAP_CHANNEL */
enum ieee80211_radiotap_channel_flags {
  IEEE80211_CHAN_CCK = 0x0020,
  IEEE80211_CHAN_OFDM = 0x0040,
  IEEE80211_CHAN_2GHZ = 0x0080,
  IEEE80211_CHAN_5GHZ = 0x0100,
  IEEE80211_CHAN_DYN = 0x0400,
  IEEE80211_CHAN_HALF = 0x4000,
  IEEE80211_CHAN_QUARTER = 0x8000,
};

/* for IEEE80211_RADIOTAP_RX_FLAGS */
enum ieee80211_radiotap_rx_flags {
  IEEE80211_RADIOTAP_F_RX_BADPLCP = 0x0002,
};

/* for IEEE80211_RADIOTAP_TX_FLAGS */
enum ieee80211_radiotap_tx_flags {
  IEEE80211_RADIOTAP_F_TX_FAIL = 0x0001,
  IEEE80211_RADIOTAP_F_TX_CTS = 0x0002,
  IEEE80211_RADIOTAP_F_TX_RTS = 0x0004,
  IEEE80211_RADIOTAP_F_TX_NOACK = 0x0008,
};

/* for IEEE80211_RADIOTAP_MCS "have" flags */
enum ieee80211_radiotap_mcs_have {
  IEEE80211_RADIOTAP_MCS_HAVE_BW = 0x01,
  IEEE80211_RADIOTAP_MCS_HAVE_MCS = 0x02,
  IEEE80211_RADIOTAP_MCS_HAVE_GI = 0x04,
  IEEE80211_RADIOTAP_MCS_HAVE_FMT = 0x08,
  IEEE80211_RADIOTAP_MCS_HAVE_FEC = 0x10,
  IEEE80211_RADIOTAP_MCS_HAVE_STBC = 0x20,
};

enum ieee80211_radiotap_mcs_flags {
  IEEE80211_RADIOTAP_MCS_BW_MASK = 0x03,
  IEEE80211_RADIOTAP_MCS_BW_20 = 0,
  IEEE80211_RADIOTAP_MCS_BW_40 = 1,
  IEEE80211_RADIOTAP_MCS_BW_20L = 2,
  IEEE80211_RADIOTAP_MCS_BW_20U = 3,

  IEEE80211_RADIOTAP_MCS_SGI = 0x04,
  IEEE80211_RADIOTAP_MCS_FMT_GF = 0x08,
  IEEE80211_RADIOTAP_MCS_FEC_LDPC = 0x10,
  IEEE80211_RADIOTAP_MCS_STBC_MASK = 0x60,
  IEEE80211_RADIOTAP_MCS_STBC_1 = 1,
  IEEE80211_RADIOTAP_MCS_STBC_2 = 2,
  IEEE80211_RADIOTAP_MCS_STBC_3 = 3,
  IEEE80211_RADIOTAP_MCS_STBC_SHIFT = 5,
};

/* for IEEE80211_RADIOTAP_AMPDU_STATUS */
enum ieee80211_radiotap_ampdu_flags {
  IEEE80211_RADIOTAP_AMPDU_REPORT_ZEROLEN = 0x0001,
  IEEE80211_RADIOTAP_AMPDU_IS_ZEROLEN = 0x0002,
  IEEE80211_RADIOTAP_AMPDU_LAST_KNOWN = 0x0004,
  IEEE80211_RADIOTAP_AMPDU_IS_LAST = 0x0008,
  IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_ERR = 0x0010,
  IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_KNOWN = 0x0020,
};

/* for IEEE80211_RADIOTAP_VHT */
enum ieee80211_radiotap_vht_known {
  IEEE80211_RADIOTAP_VHT_KNOWN_STBC = 0x0001,
  IEEE80211_RADIOTAP_VHT_KNOWN_TXOP_PS_NA = 0x0002,
  IEEE80211_RADIOTAP_VHT_KNOWN_GI = 0x0004,
  IEEE80211_RADIOTAP_VHT_KNOWN_SGI_NSYM_DIS = 0x0008,
  IEEE80211_RADIOTAP_VHT_KNOWN_LDPC_EXTRA_OFDM_SYM = 0x0010,
  IEEE80211_RADIOTAP_VHT_KNOWN_BEAMFORMED = 0x0020,
  IEEE80211_RADIOTAP_VHT_KNOWN_BANDWIDTH = 0x0040,
  IEEE80211_RADIOTAP_VHT_KNOWN_GROUP_ID = 0x0080,
  IEEE80211_RADIOTAP_VHT_KNOWN_PARTIAL_AID = 0x0100,
};

enum ieee80211_radiotap_vht_flags {
  IEEE80211_RADIOTAP_VHT_FLAG_STBC = 0x01,
  IEEE80211_RADIOTAP_VHT_FLAG_TXOP_PS_NA = 0x02,
  IEEE80211_RADIOTAP_VHT_FLAG_SGI = 0x04,
  IEEE80211_RADIOTAP_VHT_FLAG_SGI_NSYM_M10_9 = 0x08,
  IEEE80211_RADIOTAP_VHT_FLAG_LDPC_EXTRA_OFDM_SYM = 0x10,
  IEEE80211_RADIOTAP_VHT_FLAG_BEAMFORMED = 0x20,
};

enum ieee80211_radiotap_vht_coding {
  IEEE80211_RADIOTAP_CODING_LDPC_USER0 = 0x01,
  IEEE80211_RADIOTAP_CODING_LDPC_USER1 = 0x02,
  IEEE80211_RADIOTAP_CODING_LDPC_USER2 = 0x04,
  IEEE80211_RADIOTAP_CODING_LDPC_USER3 = 0x08,
};

/* for IEEE80211_RADIOTAP_TIMESTAMP */
enum ieee80211_radiotap_timestamp_unit_spos {
  IEEE80211_RADIOTAP_TIMESTAMP_UNIT_MASK = 0x000F,
  IEEE80211_RADIOTAP_TIMESTAMP_UNIT_MS = 0x0000,
  IEEE80211_RADIOTAP_TIMESTAMP_UNIT_US = 0x0001,
  IEEE80211_RADIOTAP_TIMESTAMP_UNIT_NS = 0x0003,
  IEEE80211_RADIOTAP_TIMESTAMP_SPOS_MASK = 0x00F0,
  IEEE80211_RADIOTAP_TIMESTAMP_SPOS_BEGIN_MDPU = 0x0000,
  IEEE80211_RADIOTAP_TIMESTAMP_SPOS_PLCP_SIG_ACQ = 0x0010,
  IEEE80211_RADIOTAP_TIMESTAMP_SPOS_EO_PPDU = 0x0020,
  IEEE80211_RADIOTAP_TIMESTAMP_SPOS_EO_MPDU = 0x0030,
  IEEE80211_RADIOTAP_TIMESTAMP_SPOS_UNKNOWN = 0x00F0,
};

enum ieee80211_radiotap_timestamp_flags {
  IEEE80211_RADIOTAP_TIMESTAMP_FLAG_64BIT = 0x00,
  IEEE80211_RADIOTAP_TIMESTAMP_FLAG_32BIT = 0x01,
  IEEE80211_RADIOTAP_TIMESTAMP_FLAG_ACCURACY = 0x02,
};

#endif /* __RADIOTAP_H */
