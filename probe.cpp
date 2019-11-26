/*
FileName	: probe.cpp
Author		: Sean Alexander
Creation    : 4/12/2017

Description  	:
    This file provides the functionality for the packet injection
    to create the probe requests.  The CRC code was taken from
    an example on stack overflow.

    http://stackoverflow.com/questions/11523844/802-11-fcs-crc32
*/

#include "probe.h"
#include <string.h> // needed for memcpy
#include <iomanip>

char pcap_errbuf[PCAP_ERRBUF_SIZE];

// Open the PCAP handle for injection.
bool OpenPCAPHandle(const char *interface, pcap_t** pProbeHandle)
{
    // set the buffer to empty
    pcap_errbuf[0]='\0';

    // Open the PCAP handle for injection.
    pcap_t* pcap=pcap_open_live(interface,  1024, 0,  0,  pcap_errbuf);
    if (  pcap == nullptr  )
    {
        std::cout << "%s" << pcap_errbuf << std::endl;
        return false;
    }

    // return the handle through the pointer in the parameter.
    *pProbeHandle = pcap;

    return true;
}

#include <sstream>

// all of this is little-endian
// The radio tap header needs to be included when
// creating the outgoing packet. Learned that the
// hard way.  Borrowed this from an example
// with some modifications for my purposes.
// https://gist.github.com/jonhoo/7780260
uint8_t radiotaphdr[] =
{
    0x00, 0x00, // version 2 bytes
    0x18, 0x00, // size of header

    /**
    * The next field is a bitmap of which options we are including.
    * The full list of which field is which option is in ieee80211_radiotap.h,
    *   0x00 0x01: timestamp
    *   0x00 0x02: flags
    *   0x00 0x03: rate
    *   0x00 0x04: channel
    */
    0x0f, 0x00, 0x00, 0x00,

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp

    /**
    * This is the first set of flags, and we've set the bit corresponding to
    * IEEE80211_RADIOTAP_F_FCS, meaning we want the card to add a FCS at the end
    * of our buffer for us.
    */
    0x10,

    0x00, // <-- rate
    0x00, 0x00, 0x00, 0x00, // <-- channel

    /**
    * This is the second set of flags, specifically related to transmissions. The
    * bit we've set is IEEE80211_RADIOTAP_F_TX_NOACK, which means the card won't
    * wait for an ACK for this frame, and that it won't retry if it doesn't get
    * one.
    */
    0x08, 0x00
};

// MAC Frame header.  With the little endian requirement
// it was easier to build this long hand looking at a
// wire shark display of a request probe.
uint8_t proberequestframehdr[] =
{
    0x40, 0x00, // frame control header
    0x00, 0x00, // duration microseconds
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //Recv Broadcast MAC Address
    0x84, 0x16, 0xfa, 0xaa, 0xaa, 0xaa, //Transmiter addy
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //Recv Broadcast MAC Address
    0xf0, 0x0f                        //fragment 0 sequence 255
};

// same as above.
uint8_t supportedRates[] =
{
    0x01,       // supported rates
    0x04,       // 4 rates
    0x02,       // 2
    0x04,       // 4
    0x0b,       // 5.5
    0x16        // 11
};

// CRC Function for calculating the FCS of the
// probe frame.  Taken from
// http://stackoverflow.com/questions/11523844/802-11-fcs-crc32
// I read up on it, but still don't quite understand the math.
uint32_t crc32(uint32_t bytes_sz, const uint8_t *bytes)
{
   uint32_t crc = ~0;
   uint32_t i;
   for(i = 0; i < bytes_sz; ++i) {
      crc = crctable[(crc ^ bytes[i]) & 0xff] ^ (crc >> 8);
   }
   return ~crc;
}

// All of the frame are in little endian
// wrote this to convert the FCS before inserting it into
// the outgoing packet.
uint32_t swap(uint32_t value)
{
    return (((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) | ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24));
}

// construct the frame and send it with the pcap_sendpacket command.
bool SendProbeRequest(std::string SSID,
                      pcap_t *PcapHandle)
{
    // pre-calculate the buffer size for the display
    unsigned int iBufferSize = sizeof(radiotaphdr)
                                + sizeof(proberequestframehdr)
                                + 2 + SSID.size()
                                + sizeof(supportedRates)
                                + 4; //FSC

    // create a buffer to build the frame
    uint8_t pBuffer[1024] = {0};

    // create a pointer to the frame check sequence
    uint8_t *pFcs = static_cast<uint8_t*>(pBuffer + sizeof(radiotaphdr)
                                                         + sizeof(proberequestframehdr)
                                                         + 2 + SSID.size()
                                                         + sizeof(supportedRates));

    // add radio tap header
    memcpy(static_cast<void*>(pBuffer), radiotaphdr, sizeof(radiotaphdr));

    // add probe request header
    memcpy(static_cast<void*>(&pBuffer[sizeof(radiotaphdr)]), proberequestframehdr, sizeof(proberequestframehdr));

    // create a pointer to the SSID portion of the output frame
    uint8_t *pSSID = static_cast<uint8_t*>(&pBuffer[sizeof(radiotaphdr) + sizeof(proberequestframehdr)]);

    // SSID
    pSSID[0] = 0;  // Element ID specifying SSID
    pSSID[1] = SSID.size();
    memcpy(static_cast<void*>(&pSSID[2]), SSID.c_str(), SSID.size());

    // add rates
    uint8_t *rates = pSSID + 2 + SSID.size();
    memcpy(static_cast<void*>(rates), supportedRates, sizeof(supportedRates));

    // calculate the FCS for the packet.  This does not include the radio tap header.
    uint32_t fcs = crc32(iBufferSize - sizeof(radiotaphdr) - 4, pBuffer + sizeof(radiotaphdr));
    memcpy(static_cast<void*>(pFcs), static_cast<void*>(&fcs), sizeof(unsigned long));

    unsigned int p = 0;

    // Display the outgoing packet in hex in a nicely formated manner... because... cool.
    while(p < iBufferSize)
    {
        for(int j = 0; j < 8; ++j)
        {
            if(p < iBufferSize)
            {
                std::cout << "0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(pBuffer[p++]) << " ";
            }
        }

            std::cout << " ";

        for(int j = 0; j < 8; ++j)
        {
            if(p < iBufferSize)
            {
                std::cout << "0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(pBuffer[p++]) << " ";
            }
        }

        std::cout << std::endl;
    }

    // Send the packet off.
    if( pcap_sendpacket( PcapHandle, pBuffer, iBufferSize) != 0 )
    {
        std::cout << "Packet injection failed";
        return false;
    }

    // It is finished.
    return true;
}
