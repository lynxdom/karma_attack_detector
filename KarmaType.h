#include <map>
#include <string>
#include <semaphore.h>
#include <pthread.h>

#include "HardwareAddress.h"

#ifndef _KARMATYPE_H_
#define _KARMATYPE_H_


typedef std::map<std::string, HardwareAddress> RequestMap;

struct PCAPData
{
    // network interface name
    std::string sInterface;

    // handles for closing
    pcap_t *pProbeHandle;
    pcap_t *pSnifferHandle;

    // sent address to verify attack
    HardwareAddress sentAddress;

    // semaphore to syncronize the threads
    sem_t mutex;
};

#endif
