#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


//Ethernet packet header
struct eth_header {
  u_char  destination_mac[6], source_mac[6]; //from, to mac addresses
  u_short type;
};


void intercept_ethernet_packet() {
    //Want to do a basic sanity check - is the packet header of the required length? (ethernet header length is 14 bytes)
    if() {

    }

}

void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
    //struct ether_header * eth_header = (struct ether_header *) data;
    //printf("\nType: %hu\n", eth_header->ether_type);
}
