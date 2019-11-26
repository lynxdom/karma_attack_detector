#ifndef __SNIFFER_H__
#define __SNIFFER_H__


#include <iostream>
#include <string>

#include <linux/types.h>
#include <pcap.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdint.h>

#include "KarmaType.h"

// MAC Header used in a wifi-Frame.
// This is defined in some Linux
// headers, but there were some many
// extra dependencies.  It was easier
// to cut and paste it.
struct ieee80211_hdr {
	// Frame Control contains the
	// bits that define the frame type
    uint16_t frame_control;

    uint16_t duration_id;

	// MAC Addresses associated with
	// Source, Destination, and the BSS
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
	// Controls fragmentation
    uint16_t seq_ctrl;
    uint8_t addr4[6];
} __attribute__ ((packed));

// Radio tap header
// Again, there is an include, but
// the dependencies were a pain.
struct ieee80211_radiotap_hdr {
    // Version is still 00
    uint8_t it_version;
    // Padding to keep align the struct
    uint8_t it_pad;
    // The full length of the header.
    uint16_t it_len;
    // a 32 bit value that when masked
    // indicates the present fields
    // in the Radio Tap Header.
    uint32_t it_present;
} __attribute__ ((packed));

// The masks and their corresponding purposes
const uint32_t IEEE80211_RADIOTAP_TSFT                  = 0b00000000000000000000000000000001;
const uint32_t IEEE80211_RADIOTAP_FLAGS                 = 0b00000000000000000000000000000010;
const uint32_t IEEE80211_RADIOTAP_RATE                  = 0b00000000000000000000000000000100;
const uint32_t IEEE80211_RADIOTAP_CHANNEL               = 0b00000000000000000000000000001000;
const uint32_t IEEE80211_RADIOTAP_FHSS                  = 0b00000000000000000000000000010000;
const uint32_t IEEE80211_RADIOTAP_DBM_ANTSIGNAL         = 0b00000000000000000000000000100000;
const uint32_t IEEE80211_RADIOTAP_DBM_ANTNOISE          = 0b00000000000000000000000001000000;
const uint32_t IEEE80211_RADIOTAP_LOCK_QUALITY          = 0b00000000000000000000000010000000;
const uint32_t IEEE80211_RADIOTAP_TX_ATTENUATION        = 0b00000000000000000000000100000000;
const uint32_t IEEE80211_RADIOTAP_DB_TX_ATTENUATION     = 0b00000000000000000000001000000000;
const uint32_t IEEE80211_RADIOTAP_DBM_TX_POWER          = 0b00000000000000000000010000000000;
const uint32_t IEEE80211_RADIOTAP_ANTENNA               = 0b00000000000000000000100000000000;
const uint32_t IEEE80211_RADIOTAP_DB_ANTSIGNAL          = 0b00000000000000000001000000000000;
const uint32_t IEEE80211_RADIOTAP_DB_ANTNOISE           = 0b00000000000000000010000000000000;
const uint32_t IEEE80211_RADIOTAP_EXT                   = 0b10000000000000000000000000000000;

// A function to display the radio tap data in a formated.
bool PrintRadioTapHeaderInfo(struct pcap_pkthdr *hdr, const u_char *pPacket);

// A function to display the MAC frame header in a formated way.
bool PrintFrameData(const u_char *pPacket);

// Function that handles the sniffing of management packets.
bool StartResponseSniffer(const char *sInterface,
                          pcap_t **pSniffDev,
                          PCAPData *data);

#endif // __SNIFFER_H__
