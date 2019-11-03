#include "analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

// void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
//     //Boolean values for whether the packet currently being analysed is either Arp or blacklisted (telegraph.co.uk)
//     unsigned char isArp = 0;
//     unsigned char isBlacklisted = 0;

//     //Built in TCP header and IP headers from within linux (netinet.h)
//     struct tcphdr *tcpHead;
//     struct ip *ipHead;

//     //Packet without the headers, will be a TCP packet
//     unsigned char *packetPayload;

//     struct ether_header *ethHead = (struct ether_header *) packet;
//     const unsigned char *ethPayload = packet + ETH_HLEN; //the actual packet data will start after the header finishes, which is 14 octets (18 bytes)

//     //IPv4 Packet check (they have ethernet type of 8, ntohs type 2048)
//     if (ntohs(ethHead->ether_type) == ETH_P_IP) {
//         ipHead = (struct ip *) ethPayload;
//         const unsigned char *ipPayload = packet + ETH_HLEN + (ipHead->ip_hl*4);

//         if (ipHead->ip_p == IPPROTO_TCP) {
//             tcpHead = (struct tcphdr *) ipPayload;
//             packetPayload = packet + ETH_HLEN + (ipHead->ip_hl*4) + (tcpHead->doff*4);
//         }
//     }
    
//     //At this point the packet has been parsed, we now need to analyse it for the bad stuff!

//     //ARP Packet check, these packets have an ethernet type of 2058
//     if (ntohs(ethHead->ether_type) == ETH_P_ARP) {
//         isArp++;
//     }

//     if (tcpHead != NULL) {
//         if (ntohs(tcpHead->dest) == 80 || ntohs(tcpHead->dest) == 8080) {
//             unsigned char *substr = strstr(packetPayload, "Host:");
//             if (substr != NULL)
//             if (strstr(substr, "telegraph.co.uk") != NULL) {
//                 isBlacklisted++;
//             }
//         }
//     }

//     printf(
//         "\tHeader length: 0x%.2X\n", (unsigned)(ipHead->ip_hl & 0xF) * 4
//     );




//     //Print some packet information if verbose enabled.
//     if (verbose) {
//         printf("=======[ Packet-%d ]=======\n", i);

//         //IPv4 Check
//         if (ntohs(ethHead->ether_type) == ETH_P_IP) {
//             printf("Source IP address: %d\n", ipHead->ip_src);
//             if (ipHead->ip_p == IPPROTO_TCP) {
//                 printf("IS TCP\n");
//             }
//         }
        



//         //Arp
//         if (isArp > 0) {
//             printf("ARP: \u2714\n");
//         } else {
//             printf("ARP: \u274c\n");
//         }

//         //Blacklisted
//         if (isBlacklisted > 0) {
//             printf("Blacklisted: \u2714\n");
//         } else {
//             printf("Blacklisted: \u274c\n");
//         }

//         printf("\n");

//         printf("========================\n\n\n\n\n");
//     }

//     i++;
// }

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

        if (verbose) printf("IP Header Length (Bytes): %u\n", IPHeader->ip_hl*4);
        if (verbose) printf("IP Packet Length: %hu\n", IPHeader->ip_len);
        
        //As all TCP packets are carried in IP packets, we can now check for a TCP packet existing.
        if (IPHeader->ip_p == IPPROTO_TCP) {
            TCPHeader = (struct tcphdr *) IPPayload;

            if (verbose) printf("TCP Source Port: %d\n", ntohs(TCPHeader->source));
            if (verbose) printf("TCP Destination Port: %d\n", ntohs(TCPHeader->source));

            //Packet payload found after the ethernet header, the ip header and the tcp header
            //doff = data offset
            packetPayload = packet + ETH_HLEN + (IPHeader->ip_hl*4) + (TCPHeader->doff*4);
        }
    }

    //We have now checked the Ethernet header, IP header and a possible TCP header.
    //Couldnt find a good ARP header struct in netinet, will make my own.

    struct arphdr {
        u_short htype,      //Hardware Type, e.g Ethernet = 1
                ptype;      //Protocol Type, Share the same values as the EtherType
        u_char  hlen,       //Hardware Address Length, e.g Ethernet = 6
                plen;       //Protocol Address Length, e.g IPv4 = 4
        u_short oper,       //Operation, 1 = request, 2 = reply
                sha[3],     //Sender Hardware Address
                spa[2],     //Sender Protocol Address
                tha[3],     //Target Hardware Address
                tpa[2];     //Target Protocol Address
    };

    if(ntohs(ethernetHeader->type) == ETH_TYPE_ARP)

    if (verbose) printf("=================================\n\n\n");
    i++;
}