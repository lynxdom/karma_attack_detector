/*
FileName	: KarmaDetection.cpp
Author		: Sean Alexander
Creation    : 4/12/2017

Description  	:
	This program is a proof of concept for a Karma Attack
	defense taking advantage of the fact a Karma Attack responds
	to all directed probes.

	This program uses two threads.  One thread is responsible for
	creating regular, spurious, probe requests.  The other thread
	uses a sniffer that is going through all management frames,
	looking for any responses that are directed and the probe
	provided MAC address.
*/

// standard I/O
#include <iostream>

// Use PCAP for our capture
#include <pcap.h>

// Functionality for the
// probe and sniffer threads
#include "sniffer.h"
#include "probe.h"

// sleep function
#include <unistd.h>

// Currently holds a common data structure
// to pass data between the threads.
#include "KarmaType.h"

// list of false SSID's gotten from
// the top of the 1000 common SSID names.
// in a more complete solution these
// would be generated more programmatically
// to give more randomness.
std::string sCommonNames[] = {"lynxdom",
                              "xfinitywifi13",
                              "linksys43",
                              "BTWiFi-with-FON54",
                              "NETGEAR32",
                              "BTWifi-X34",
                              "Ziggo78",
                              "dlink54",
                              "lynxdom"};






// prototype thread functions
void *SnifferThread(void* param);
void *ProbeThread(void* param);

// main routine
int main(int iArgs, char** ppArgs)
{
    // String to store the name
    // of the interface to be
    // used.
    std::string sDeviceName;

    // The argument passed to
    // the command line can
    // be used to specify a network
    // interface.
    if(iArgs != 2)
    {
        // set the device to the default
        // monitor interface
        sDeviceName = "wlan3";
    }
    else
    {
        // set the interface to the argument
        sDeviceName = ppArgs[1];
    }

    // Thread handles to control
    // the threads.
    pthread_t snifferThreadHandle;
    pthread_t probeThreadHandle;

    // Variable to share data
    // between the threads.
    PCAPData data;

    // Set the network interface name
    data.sInterface = sDeviceName;

    // helps with debugging
    data.pProbeHandle = nullptr;
    data.pSnifferHandle = nullptr;

    // Set the mutex semaphore to 1
    // that there is mutual exclusion
    // around the console.
    sem_init(&data.mutex, 0, 1);

    // Create the sniffer thread to
    // listen to management frames to seek probe responses with
    // a specified MAC address.
    if( pthread_create(&snifferThreadHandle, nullptr, &SnifferThread, static_cast<void*>(&data)) != 0)
    {
        std::cout << "Unable to start sniffer thread!" << std::endl;
        return -1;
    }

    // Give the sniffer a chance to fire up.
    sleep(4);

    // Create a probe thread that sends out 100 probe
    // requests, that have a 5 second pause, to entice a Karma Attack device
    // to respond.
    if( pthread_create(&probeThreadHandle, nullptr, &ProbeThread, static_cast<void*>(&data)) != 0)
    {
        std::cout << "Unable to start probe thread!" << std::endl;
        return -1;
    }

    // Join the main process to the probe thread to
    // keep the program active as long as there a probes to be sent/
    pthread_join(probeThreadHandle, nullptr);


    // Close the interface device
    pcap_close(data.pProbeHandle);
    pcap_close(data.pSnifferHandle);

    // terminate program
    return 0;
}

// Thread running the sniffer task
// of the process.
void *SnifferThread(void* param)
{
    // cast the initial data from the
    // threads creating to the PCAPData type.
    PCAPData *data = static_cast<PCAPData *>(param);

    // Start the sniffer using the parameter
    // from the data structure.  Should have
    // just passed the structure, but too far in
    // to fix it now.
    StartResponseSniffer( data->sInterface.c_str(),
                          &data->pSnifferHandle,
                          data);

    // There is no relevant data
    // to be returned.
    return nullptr;
}

// Thread routine that sends the probe requests
void *ProbeThread(void* param)
{
    // Display the start of the probe thread staring
    std::cout << "Probe Thread Started..." << std::endl;

    // cast the initial data from the
    // threads creating to the PCAPData type.
    PCAPData *data = static_cast<PCAPData *>(param);

    // In a more complete solution this would
    // be generated on a per request basis and
    // added to a table.  This will work just
    // to prove the concept.
    // 0x84, 0x16, 0xfa, 0xaa, 0xaa, 0xaa
    data->sentAddress.A = 0x84;
    data->sentAddress.B = 0x16;
    data->sentAddress.C = 0xfa;
    data->sentAddress.D = 0xaa;
    data->sentAddress.E = 0xaa;
    data->sentAddress.F = 0xaa;

    // Open the PCAP handle for the packet injection.
    if(OpenPCAPHandle( data->sInterface.c_str(), &data->pProbeHandle ))
    {

        // Send 100 probe requests to demonstrate the concept.
        for(int i = 0; i < 100; ++i)
        {

            // Provide mutual exclusion to the output so the
            // formating doesn't get mangled.
            sem_wait( &data->mutex );

            // Indicate what SSID is being used.
            std::cout << "Sending Probe Request : " << sCommonNames[i % 8] << std::endl;

            // Send the request
            SendProbeRequest( std::string(sCommonNames[i % 8]), data->pProbeHandle);

            // add a space to look cleaner
            std::cout << std::endl;

            //release the thread to allow the sniffer access to the
            // output.
            sem_post( &data->mutex );

            // wait for the thread to have time to go through
            // the management frames, and in heavy network traffic
            // there is a lot of data to go through.
            sleep(7);
        }
    }

    // There is no relevant data
    // to be returned.
    return nullptr;
}
