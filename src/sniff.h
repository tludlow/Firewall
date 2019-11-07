#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

#include "linkedlist.h"

void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);

#endif
