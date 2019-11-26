/*
FileName	: sniffer.cpp
Author		: Sean Alexander
Creation    : 4/12/2017

Description  	:
	This file contains the functionality for the
	sniffing portion of the program
*/
#include "sniffer.h"

#include <sstream>

#include <stdlib.h>
#include <string.h>

#include <iomanip>
#include <bitset>

//error buffer for PCAP return.
char pErrbuf[PCAP_ERRBUF_SIZE];

// Callback for the pcap_loop function.
void PacketProcessCallback(u_char *user,
                           const struct pcap_pkthdr* hdr,
                           const u_char* pPacket)
{

}

// Helper function to get the SSID
// from a management frame.
void GetSSID(const u_char *pPacket,
             std::string &SSID,
             int iHeaderSize)
{
    uint8_t length;
    char pSSID[32] = {0};

    memcpy(static_cast<void*>(&length), static_cast<void*>(const_cast<u_char*>(pPacket) + iHeaderSize + 24 + 8 + 4 + 1), 1);
    memcpy(&pSSID, static_cast<void*>(const_cast<u_char*>(pPacket) + iHeaderSize + 24 + 8 + 4 + 2), length);

    SSID = pSSID;
}

// Get the Source MAC Address from the
// from the management frame body.
void GetSourceAddy(const u_char *pPacket,
                   HardwareAddress &dest,
                   int iHeaderSize)
{
    unsigned char r_dmac[6];

    // Memcpy the data from the packet buffer.
    memcpy(static_cast<void*>(&r_dmac), static_cast<void*>(const_cast<u_char*>(pPacket) + iHeaderSize + 10), 6);

    dest.A = r_dmac[0];
    dest.B = r_dmac[1];
    dest.C = r_dmac[2];
    dest.D = r_dmac[3];
    dest.E = r_dmac[4];
    dest.F = r_dmac[5];
}

// Get the Destination MAC Address from the
// from the management frame body.
void GetDestAddy(const u_char *pPacket,
                 HardwareAddress &dest,
                 int iHeaderSize)
{
    unsigned char r_dmac[6];

    // Memcpy the data from the packet buffer.
    memcpy(static_cast<void*>(&r_dmac), static_cast<void*>(const_cast<u_char*>(pPacket) + iHeaderSize + 4), 6);

    dest.A = r_dmac[0];
    dest.B = r_dmac[1];
    dest.C = r_dmac[2];
    dest.D = r_dmac[3];
    dest.E = r_dmac[4];
    dest.F = r_dmac[5];
}

// initilize our sniffer handle and start
// looking for the false SSID's
bool StartResponseSniffer(const char *sInterface,
                          pcap_t **pSniffDev,
                          PCAPData *data)
{
    // Berkley Packet Filter structure
    // The Berkeley Packet Filter (BPF) provides a raw interface to
    // data link layers, permitting raw link-layer packets to be sent and received.
    struct  bpf_program fp;

    // initialize the return to nullptr
    *pSniffDev = nullptr;

    // handle to sniffing device
    pcap_t *pNetworkInterface = nullptr;

    // create a PCAP handle to a network interface
    pNetworkInterface = pcap_create(sInterface, pErrbuf);
    if( pNetworkInterface == nullptr )
    {
        std::cout << "error opening PCAP interface!" << std::endl;
        return false;
    }

    // pass back the handle so it can be closed by
    // the main program.
    *pSniffDev = pNetworkInterface;

    // verify we can put this device into monitor mode
    if( pcap_can_set_rfmon(pNetworkInterface) == 0 )
    {
        std::cout << "Monitor mode can not be set." << std::endl;
        return false;
    }

    // if we got this far put the device into monitor mode.
     if( pcap_set_rfmon(pNetworkInterface, 1) != 0 )
    {
        std::cout << "Failed to set monitor mode." << std::endl;
        return false;
     }

     // promiscuous mode for sniffing the management
     // frames
     if( pcap_set_promisc(pNetworkInterface, 1) != 0)
     {
        std::cout << "Failed to set promiscous mode." << std::endl;
        return false;
     }

    // activate the sniffing!  My dog has no nose.
    // how does it smell?  With PCAP!
    if( pcap_activate(pNetworkInterface) != 0 )
    {
        std::cout << "pcap_activate() failed" << std::endl;
        return false;
    }

    // verify that is an 802.11 interface
    if( pcap_datalink(pNetworkInterface) != DLT_IEEE802_11_RADIO )
    {
        std::cout << "This program requires a wireless interface" << std::endl;
        return false;
    }

    // create the filter to be compiled into the
    // pcap handle.  I was toying with the idea
    // of restricting it further to response
    // sub types, but left it like this if I wanted
    // to toy with detecting evil twin by associating
    // MAC Addresses with SSID's
    std::string sFilter = "type mgt";


     //  Compile a filter to sniff 802.11 probe requests
     // type mgt subtype probe-req
    if( pcap_compile(pNetworkInterface, &fp, sFilter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 )
    {
        printf("pcap_compile() failed: %s\n", pcap_geterr(pNetworkInterface));
        return false;
    }


    // Set the compiled filter
    if( pcap_setfilter(pNetworkInterface, &fp) == -1 )
    {
        printf("pcap_setfilter() failed: %s\n", pcap_geterr(pNetworkInterface));
        exit(EXIT_FAILURE);
    }

    // clean up the space
    pcap_freecode(&fp);

    // simple message to let the outside world know what's
    // up.
    std::cout << "Starting sniffer!" << std::endl;

    // start the sniffer loop
    // Started by implementing pcap_loop, but
    // found that this gave a greater level of
    // control.

    // This whole thing is a little bit of a mess, but, again,
    // this program is a proof of concept.  An object library
    // containing the functionality presented here would be
    // the next step.
    while(1)
    {
        // This is as struct returned by
        // pcap_next to give info about the packet returned.
        struct pcap_pkthdr hdr;

        // Get the next packet
        const u_char *pPacket = pcap_next(pNetworkInterface, &hdr);

        // This would be REALLY weird, but
        // not necessarily catastrophic.
        if( pPacket == nullptr )
        {
            std::cout << "No packet captured";
            continue;
        }

        // Space for the SSID
        std::string sSSID;

        // Get the RadioTap header to get the size so we can
        // jump right to the wifi frame
        struct ieee80211_radiotap_hdr RadioTapHeader;
        mempcpy(static_cast<void*>(&RadioTapHeader), const_cast<u_char*>(pPacket), sizeof(struct ieee80211_radiotap_hdr));
        uint16_t iHeaderSize = RadioTapHeader.it_len;

        // get the MAC Header so we can query the frame control portion to determine
        // the frame type and address data.
        struct ieee80211_hdr mac_hdr;
        memcpy(static_cast<void*>(&mac_hdr), static_cast<void*>(const_cast<u_char*>(pPacket) + iHeaderSize), sizeof(struct ieee80211_hdr));

        // The filter in the PCAP specifies only management types, but I was skeptical at first.
        uint16_t type       = (0b000000000000001100 & mac_hdr.frame_control) >> 2;
        // Get the sub-type
        uint16_t subtype    = (0b000000000011110000 & mac_hdr.frame_control) >> 4;

        // not necessary but I was getting tired of the compiler warning
        // about the unused variable.
        if(type == 0) // Management Frame
        {
            if(subtype == 5) // Probe Response
            {
                // This is more about keeping the display clean
                // than anything else.  By putting it here
                // the packet sniffer will be able to process packets
                // faster, and will only be held up when it finds something.
                sem_wait( &data->mutex );

                // get the SSID associated with this response
                GetSSID(pPacket, sSSID, iHeaderSize);

                // Get where the frame was sent too
                HardwareAddress hwA;
                GetDestAddy(pPacket, hwA, iHeaderSize);

                // Check if the response is in response to our fake
                // request.
                if(data->sentAddress == hwA)
                {
                    // Huzza!
                    std::cout << "Karma Attack Detected!" << std::endl;

                    // Get the mac address of the malevolent device
                    HardwareAddress hwASource;
                    GetSourceAddy(pPacket, hwASource, iHeaderSize);

                    // Display the address.
                    std::cout << "SOURCE MAC ADDRESS" << std::endl;
                    std::cout << std::hex << static_cast<int>(hwASource.A) << ":"
                                          << static_cast<int>(hwASource.B) << ":"
                                          << static_cast<int>(hwASource.C) << ":"
                                          << static_cast<int>(hwASource.D) << ":"
                                          << static_cast<int>(hwASource.E) << ":"
                                          << static_cast<int>(hwASource.F) << std::dec << std::endl;


                    // Display the SSID in the response.
                    std::cout << "Probe Response" << std::endl;

                    std::cout << "SSID: "<< sSSID << std::endl;
                    std::cout << std::endl;


                    // Display the destination of the frame... which is the false
                    // MAC sent with the probe... Reasons.
                    std::cout << "DEST MAC ADDRESS" << std::endl;
                    std::cout << std::hex << static_cast<int>(hwA.A) << ":"
                                          << static_cast<int>(hwA.B) << ":"
                                          << static_cast<int>(hwA.C) << ":"
                                          << static_cast<int>(hwA.D) << ":"
                                          << static_cast<int>(hwA.E) << ":"
                                          << static_cast<int>(hwA.F) << std::dec << std::endl;

                    // PRint the Radio Tap info.  This includes the signal strength.
                    PrintRadioTapHeaderInfo(const_cast<struct pcap_pkthdr*>(&hdr), pPacket);
                }

                // Free up the mutex so the
                // probe can continue.
                sem_post( &data->mutex );
            }
        } //if(type == 0)

    }

    // The way this function is written this will never be
    // hit, but batman.
    return true;
}


// Helper function to keep track of the packet pointer
// while parsing the radio tab header.
template<typename _T>
int GetField(_T *pDestination, u_char* pSource)
{
    // copy the radio tap info to the variable provided and return
    // the size of the datafield to increment the pointer the correct length.
    memcpy( static_cast<void*>(pDestination), static_cast<void*>(pSource), sizeof(_T) );
    return sizeof(_T);
}

// Function to print out all the data in the radio tap header.  The
// data field available with the header are specified by the 'present field'
// The fields must be read in the order specified by the radiotap header org.
// http://www.radiotap.org/fields/defined
bool PrintRadioTapHeaderInfo(struct pcap_pkthdr *hdr, const u_char *pPacket)
{

    // Fields with lengths
    u_int64_t wr_tsft;
    u_int8_t wr_flags;
    u_int8_t wr_rate;
    u_int16_t wr_fhss;
    u_int16_t wr_chan_freq;
    u_int16_t wr_chan_flags;
    u_int8_t wr_antennanoise;
    u_int8_t wr_antsignal;

    struct ieee80211_radiotap_hdr pRadioHeader;
    memcpy(static_cast<void*>(&pRadioHeader), pPacket, sizeof(struct ieee80211_radiotap_hdr));

    // move the pointer to the end of the radio tap header data;
    u_char* pFieldPointer = const_cast<u_char*>(pPacket) + sizeof(struct ieee80211_radiotap_hdr);

    u_int32_t FLAGS = pRadioHeader.it_present;
    std::cout << "Radio Tap Header Flags :" << std::bitset<32>(FLAGS) << std::endl;

    // it present is a bit masked value that indicates the field data
    // stored in the radio tap header.
    if( FLAGS & IEEE80211_RADIOTAP_EXT )
    {
        // this header has a manufacturer specific field set so we need to ignore the
        // next 32 bits.

        pFieldPointer += 8;
    }

    if( FLAGS & IEEE80211_RADIOTAP_TSFT )
    {
        /*  Value in microseconds of the MAC’s 64-bit 802.11 Time Synchronization Function
            timer when the first bit of the MPDU arrived at the MAC. For received frames only.  */
        pFieldPointer += GetField( &wr_tsft, pFieldPointer);
        std::cout << "TFST :" << static_cast<unsigned int>(wr_tsft) << std::endl;
    }

    // 1 bit
    if( FLAGS & IEEE80211_RADIOTAP_FLAGS )
    {
        /* Properties of transmitted and received frames.
           Details : http://www.radiotap.org/fields/Flags.html */

        pFieldPointer += GetField( &wr_flags, pFieldPointer);
        std::cout << "Flags:" << std::bitset<8>(wr_flags) << std::endl;
    }

    // 2 bit
    if( FLAGS & IEEE80211_RADIOTAP_RATE )
    {
        /* TX/RX data rate
            500 Kbps */
        pFieldPointer += GetField( &wr_rate, pFieldPointer);
        std::cout << "Rate(500KBps) :" << static_cast<unsigned int>(wr_rate) << std::endl;
    }

    // 3 bit
    if( FLAGS & IEEE80211_RADIOTAP_CHANNEL )
    {
        /*  Tx/Rx frequency in MHz, followed by flags.
            http://www.radiotap.org/fields/Channel.html */

        pFieldPointer += GetField( &wr_chan_freq, pFieldPointer);
        std::cout << "Frequency :" << wr_chan_freq << std::endl;
        pFieldPointer += GetField( &wr_chan_flags, pFieldPointer);
        std::cout << "Flags :" << std::bitset<16>(wr_chan_freq) << std::endl;

    }

    // 4 bit
    if( FLAGS & IEEE80211_RADIOTAP_FHSS )
    {
        /*  The hop set and pattern for frequency-hopping radios. */

        pFieldPointer += GetField( &wr_fhss, pFieldPointer);
    }

    // 5 bit
    if( FLAGS & IEEE80211_RADIOTAP_DBM_ANTSIGNAL )
    {
        /* RF signal power at the antenna. This field contains a single signed 8-bit value,
           which indicates the RF signal power at the antenna, in decibels difference from 1mW. */

        pFieldPointer += GetField( &wr_antsignal, pFieldPointer);

        std::cout << "Signal(dB) :" << static_cast<int>(static_cast<char>(wr_antsignal)) << std::endl;
    }


    // 6 bit
    if( FLAGS & IEEE80211_RADIOTAP_DBM_ANTNOISE )
    {
        /* RF noise power at the antenna. This field contains a single signed 8-bit value,
           which indicates the RF signal power at the antenna, in decibels difference from 1mW. */

        pFieldPointer += GetField( &wr_antennanoise, pFieldPointer);
        std::cout << "Noise(dB)  :" << static_cast<char>(wr_antennanoise) << std::endl;
    }

    std::cout << std::endl;

    return true;
}
