#include "analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

//An ARP Reply code, these need to be logged.
#define ARP_OPER_REPLY 0x02

//Packet counter, useful for verbose debugging as many packets can appear the same.
int i = 0;

void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
    //Flags on what the packet is, used in the report after program exited.
    int isArp = 0;
    int isBlacklisted = 0;

    if (verbose) printf("=========[ PACKET-%d ]=========\n", i);

    //Convert the packet data into the ether_header struct (found in if_ether.h) - this works because of the contiguous structure of the packet/ethernet struct.
    //etherheader structure:  
    //  - u_char dest_mac[6]       - 6 octets of the destination mac address (the mac address of the current computer)
    //  - u_char src_mac[6]        - 6 octets of the source mac address
    //  - u_short ether_type;            - The type of packet. https://en.wikipedia.org/wiki/EtherType
    struct ether_header *ethernetHeader = (struct ether_header *) packet;
    if (verbose) printf("Ethernet Type: %d\n", ntohs(ethernetHeader->ether_type));

    //The contents of the ethernet packet start after the fixed header length, which is 14 octets.
    const unsigned char *ethernetPayload = packet + ETH_HLEN;

    //IP Header structure found in netinet/ip.h
    struct ip *IPHeader;

    //TCP Header structure found in netinet/tcp.h
    struct tcphdr *TCPHeader;

    //The packet payload, following the ethernet header, ip header and tcp header.
    //unsigned char *packetPayload;

    //Contents of the IP Packet, which is the packet argument with the ehternet header skipped over (ETH_HLEN) + the ip header length

    //Parse the ethernet packet to see if it is a IPv4 packet, which has a type of 8 and when corrected for endianess 2048
    //If it is a IPv4 packet, we take the ethernet payload and "load" it into the ip struct
    if(ntohs(ethernetHeader->ether_type) == ETH_P_IP) {
        IPHeader = (struct ip *) ethernetPayload; 
        const unsigned char *IPPayload = packet + ETH_HLEN + (IPHeader->ip_hl*4);

        if (verbose) {
            printf("IPv4 Packet \n");
            printf("IP Packet Length: %hu\n", IPHeader->ip_len);
            printf("IP Header Length (Bytes): %u\n", IPHeader->ip_hl*4);
            printf("IP Packet Length: %hu\n", IPHeader->ip_len);
        }
        
        //As all TCP packets are carried in IP packets, we can now check for a TCP packet existing.
        if (IPHeader->ip_p == IPPROTO_TCP) {
            TCPHeader = (struct tcphdr *) IPPayload;

            if (verbose) printf("TCP Source Port: %d\n", ntohs(TCPHeader->source));
            if (verbose) printf("TCP Destination Port: %d\n", ntohs(TCPHeader->source));

            //Packet payload found after the ethernet header, the ip header and the tcp header
            //doff = data offset
            //packetPayload = packet + ETH_HLEN + (IPHeader->ip_hl*4) + (TCPHeader->doff*4);
        }
    }

    //We have now checked the Ethernet header, IP header and a possible TCP header.

    struct ether_arp *ether_arp = NULL;

    //Check if the ethernet type is an ARP packet.
    if(ntohs(ethernetHeader->ether_type) == ETH_P_ARP) {
        if (verbose) printf("ARP Packet \u2714\u2714\u2714\u2714\n");

        isArp++;
        ether_arp = (struct ether_arp*) (packet + ETH_HLEN);

        //Correct the endianess of the data saved in the ether_arp
        //Only have to do these fields, the others arent required.
        ether_arp->ea_hdr.ar_hrd = ntohs(ether_arp->ea_hdr.ar_hrd);
        ether_arp->ea_hdr.ar_pro = ntohs(ether_arp->ea_hdr.ar_pro);
        ether_arp->ea_hdr.ar_op = ntohs(ether_arp->ea_hdr.ar_op);

        //Iterative over all the data in the arrays for the final 4 fields.
        for (i = 0; i < ETH_ALEN; ++i) ether_arp->arp_sha[i] = ntohs(ether_arp->arp_sha[i]);
        for (i = 0; i < 4; ++i) ether_arp->arp_spa[i] = ntohs(ether_arp->arp_spa[i]);
        for (i = 0; i < ETH_ALEN; ++i) ether_arp->arp_tha[i] = ntohs(ether_arp->arp_tha[i]);
        for (i = 0; i < 4; ++i) ether_arp->arp_tpa[i] = ntohs(ether_arp->arp_tpa[i]);

        if (verbose) {
            printf("[ARP] Hardware type: %s\n", (ether_arp->ea_hdr.ar_hrd) == 1 ? "Ethernet" : "??"); 
            printf("[ARP] Protocol type is: %s\n", (ether_arp->ea_hdr.ar_pro) == 0x0800 ? "IPv4" : "??"); 
            printf("[ARP] Operation: %s\n", (ether_arp->ea_hdr.ar_op) == 1 ? "ARP Request" : "ARP Reply"); 
        }  
    }


    isBlacklisted++;

    if (verbose) printf("=================================\n\n\n");
    i++;
}