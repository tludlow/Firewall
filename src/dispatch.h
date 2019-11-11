#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>
#include "linkedlist.h"
#include "queue.h"

void dispatch(u_char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void createThreadPool(List *list);
void handleSignal(int signal);
void *threadProgram(void *arg);

#endif
