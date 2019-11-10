#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>
#include "linkedlist.h"

void dispatch(struct pcap_pkthdr *header,  const unsigned char *packet, int verbose, List *linkedList);
void createThreadPool(void);
void handleSignal(int signal);
void *threadProgram(void *arg);

#endif
