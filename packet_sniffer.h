#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <iostream>
#include <ncurses.h>
#include <string>
#include <vector>
#include <pcap.h>

class Sniffer
{
public:
    bool getInterfaces(pcap_if_t *&interfaceList);
    bool startCapture(const char *selectedInterface, const char *pcapFileName);
};

#endif