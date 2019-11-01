#include "analysis.h"
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
    //Boolean values for whether the packet currently being analysed is either Arp or blacklisted (telegraph.co.uk)
    unsigned char isArp = 0;
    unsigned char isBlacklisted = 0;

    //Built in TCP header and IP headers from within linux (netinet.h)
    struct tcphdr *tcpHead;
    struct ip *ipHead;

    //Packet without the headers, will be a TCP packet
    unsigned char *packetPayload;

    struct ether_header *ethHead = (struct ether_header *) packet;
    const unsigned char *ethPayload = packet + ETH_HLEN; //the actual packet data will start after the header finishes, which is 14 octets (18 bytes)

    //IPv4 Packet check (they have ethernet type of 8, ntohs type 2048)
    if (ntohs(ethHead->ether_type) == ETH_P_IP) {
        ipHead = (struct ip *) ethPayload;
        const unsigned char *ipPayload = packet + ETH_HLEN + (ipHead->ip_hl*4);

        if (ipHead->ip_p == IPPROTO_TCP) {
            tcpHead = (struct tcphdr *) ipPayload;
            packetPayload = packet + ETH_HLEN + (ipHead->ip_hl*4) + (tcpHead->doff*4);
        }
    }
    
    //At this point the packet has been parsed, we now need to analyse it for the bad stuff!

    //ARP Packet check, these packets have an ethernet type of 2058
    if (ntohs(ethHead->ether_type) == ETH_P_ARP) {
        isArp++;
    }

    if (tcpHead != NULL) {
        if (ntohs(tcpHead->dest) == 80 || ntohs(tcpHead->dest) == 8080) {
            unsigned char *substr = strstr(packetPayload, "Host:");
            if (substr != NULL)
            if (strstr(substr, "telegraph.co.uk") != NULL) {
                isBlacklisted++;
                printf("Blacklisted\n");
                printf("Blacklisted\n");
                printf("Blacklisted\n");
                printf("Blacklisted\n");
                printf("Blacklisted\n");
                printf("Blacklisted\n");
            }
        }
    }


    //Print some packet information if verbose enabled.
    if (verbose) {
        printf("=======[ Packet ]=======\n");

        //IPv4 Check
        if (ntohs(ethHead->ether_type) == 2048) {
            printf("Type: IPv4\n");
        }

        //Arp
        if (isArp > 0) {
            printf("ARP: \u2714\n");
        } else {
            printf("ARP: \u274c\n");
        }

        //Blacklisted
        if (isBlacklisted > 0) {
            printf("Blacklisted: \u2714\n");
        } else {
            printf("Blacklisted: \u274c\n");
        }

        printf("========================\n\n\n\n\n");
    }
}
