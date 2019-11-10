#include "analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <string.h>
#include "linkedlist.h"

//An ARP Reply code, these need to be logged.
#define ARP_OPER_REPLY 0x02

//Counter for the arp responses found and blacklisted packets found. This will be thread safe
volatile unsigned long arpResponsePackets = 0;
volatile unsigned long blacklistedPackets = 0;
volatile unsigned long synPackets = 0;


void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose, List *linkedList) {
    //Convert the packet data into the ether_header struct (found in if_ether.h) - this works because of the contiguous structure of the packet/ethernet struct.
    //etherheader structure:  
    //  - u_char dest_mac[6]       - 6 octets of the destination mac address (the mac address of the current computer)
    //  - u_char src_mac[6]        - 6 octets of the source mac address
    //  - u_short ether_type;            - The type of packet. https://en.wikipedia.org/wiki/EtherType
    struct ether_header *ethernetHeader = (struct ether_header *) packet;

    //The contents of the ethernet packet start after the fixed header length, which is 14 octets.
    const unsigned char *ethernetPayload = packet + ETH_HLEN;

    //IP Header structure found in netinet/ip.h
    struct ip *IPHeader;

    //TCP Header structure found in netinet/tcp.h
    struct tcphdr *TCPHeader;

    //The packet payload, following the ethernet header, ip header and tcp header.
    unsigned char *packetPayload;

    //Contents of the IP Packet, which is the packet argument with the ehternet header skipped over (ETH_HLEN) + the ip header length

    //Parse the ethernet packet to see if it is a IPv4 packet, which has a type of 8 and when corrected for endianess 2048
    //If it is a IPv4 packet, we take the ethernet payload and "load" it into the ip struct
    if(ntohs(ethernetHeader->ether_type) == ETH_P_IP) {
        IPHeader = (struct ip *) ethernetPayload; 
        const unsigned char *IPPayload = packet + ETH_HLEN + (IPHeader->ip_hl*4);
        
        //As all TCP packets are carried in IP packets, we can now check for a TCP packet existing.
        if (IPHeader->ip_p == IPPROTO_TCP) {
            TCPHeader = (struct tcphdr *) IPPayload;

            //Packet payload found after the ethernet header, the ip header and the tcp header
            //doff = data offset
            packetPayload = packet + ETH_HLEN + (IPHeader->ip_hl*4) + (TCPHeader->doff*4);

            //Test for a SYN attack
            if (TCPHeader->syn == 1 && TCPHeader->ack == 0) {
                //Adds the sourceip and the time to the linked list.
                add(linkedList, ntohl(IPHeader->ip_src.s_addr));
                synPackets++;
            }
        }
    }

    //We have now checked the Ethernet header, IP header and a possible TCP header.

    struct ether_arp *ether_arp = NULL;

    //Check if the ethernet type is an ARP packet.
    if(ntohs(ethernetHeader->ether_type) == ETH_P_ARP) {
        //Like above, load the arp packet info into the ether_Arp struct, which starts after the ethernet header.
        ether_arp = (struct ether_arp*) (packet + ETH_HLEN);

        //When the operation of the arp packet is a reply aka reponse, we will count this as a possible cache poisoning
        if (ntohs(ether_arp->ea_hdr.ar_op) == ARPOP_REPLY) {
            //Is a response, this is bad.
            arpResponsePackets++;
        }
    }


    //Now to check whether or not the packet coming in is a TCP, HTTP packet which has the host header of "telegraph.co.uk", this is a blacklisted domain.
    int httpPort = 80;
    if(ntohs(ethernetHeader->ether_type) == ETH_P_IP) {
        if (IPHeader->ip_p == IPPROTO_TCP) {
            if (ntohs(TCPHeader->dest) == httpPort || ntohs(TCPHeader->source) == httpPort) {
                unsigned char *substr = strstr(packetPayload, "Host:");
                if (substr != NULL)
                if (strstr(substr, "telegraph.co.uk") != NULL) {
                    int j;
                    for(j = 1; j < 20; j++) {
                        printf("Malicous packet found!\n");
                    }
                    blacklistedPackets++;
                }
            }
        }
    }
}