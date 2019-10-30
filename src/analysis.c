// #include "analysis.h"

// #include <pcap.h>
// #include <netinet/if_ether.h>
// #include <netinet/ip.h>
// #include <netinet/tcp.h>

// struct ethernet_header {
//     u_char ethernetDestinationHost[6];
//     u_char ethernetSourceHost[6];
//     u_short ethernetType;
// }


// //packet argument corresponds to the data argument in the dump function within sniff.c
// void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
//     struct ether_header *eth_header = (struct ether_header *) packet;
//     printf("\nType: %hu\n", eth_header->ethernetType);


// }



#include "analysis.h"
#include "dispatch.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>


void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
    int i;
    unsigned char isXmas = 0;
    unsigned char isArp = 0;
    unsigned char isHtml = 0;

    //Built in TCP header and IP headers from within linux
    struct tcphdr *tcphead;
    struct ip *iphead;


    struct ether_header *ethhead = (struct ether_header *) packet;
    const unsigned char *ethpayload = packet + ETH_HLEN; //the actual packet data will start after the header finishes, which is 14 octets (18 bytes)

    //IPv4 packets have ethernet type of 8.
    if (ntohs(ethhead->ether_type) == ETH_P_IP) {
        iphead = (struct ip *) ethpayload;
        const unsigned char *ippayload = packet + ETH_HLEN + iphead->ip_hl*4;

        if (iphead->ip_p == IPPROTO_TCP) {
            tcphead = (struct tcphdr *) ippayload;
            packetpayload = packet + ETH_HLEN + iphead->ip_hl * 4 + tcphead->doff * 4 ;
        }
    }

    //At this point the packet has been parsed, we now need to analyse it for the bad stuff!

    //Start our XMAS scan if the packet is tcp.
    if (tcphead != NULL) {
        if (tcphead->urg && tcphead->psh && tcphead->fin) {
            isXmas++;
            if (verbose) printf("XMAS FOUND\n");
        } else if (verbose) printf("XMAS NOT FOUND\n");
    }

    //Start our ARP search
    if (ntohs(ethhead->ether_type) == ETH_P_ARP) {
        isArp++;
        if (verbose) printf("ARP FOUND\n");
    } else if (verbose) printf("ARP NOT FOUND\n");

    //Start our BLACKLIST scan if the port is 80 or 8080 ie html/htmls
    if (tcphead != NULL) {
        //Check that the packet is either coming from port 80 - HTTP port or port 8080 which is a popular alternative for HTML
        if (ntohs(tcphead->dest) == 80 || ntohs(tcphead->dest) == 8080) {
            unsigned char *substr = strstr(packetpayload, "Host:");
            if (substr != NULL)
            if (strstr(substr, "bbc.co.uk") != NULL) {
                isHtml++;
                if (verbose) printf("MALICIOUS HTML FOUND");
            } else if (verbose) printf("MALCIOUS HTML NOT FOUND");
        }
    }
}
