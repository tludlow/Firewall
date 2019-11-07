#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>
#include "linkedlist.h"

extern volatile unsigned long arpResponsePackets;
extern volatile unsigned long blacklistedPackets;
extern volatile unsigned long synPackets;

void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose, List *linkedList);

#endif
