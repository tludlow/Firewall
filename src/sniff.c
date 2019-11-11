#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "linkedlist.h"
#include "dispatch.h"
#include "queue.h"

struct dispatchArgs {
    int verbose;
    List *linkedList;
};

// Application main sniffing loop
void sniff(char *interface, int verbose) {
    //Linked list to store potential SYN attack packets.
    List *linkedList = createList();

    // Open network interface for packet capture
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);

    if (pcap_handle == NULL) {
        fprintf(stderr, "Unable to open interface %s\n", errbuf);
        exit(EXIT_FAILURE);
    } else {
        printf("SUCCESS! Opened %s for capture\n", interface);

    }

    //Create the thread pool if not running in verbose.
    if(!verbose) {
        createThreadPool(linkedList);
    }

    struct dispatchArgs dArgs = {verbose, linkedList};

    signal(SIGINT, handleSignal);
    pcap_loop(pcap_handle, -1, (pcap_handler) dispatch, (u_char *) &dArgs);
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
    unsigned int i;
    static unsigned long pcount = 0;
    // Decode Packet Header
    struct ether_header *eth_header = (struct ether_header *) data;
    printf("\n\n === PACKET %ld HEADER ===", pcount);
    printf("\nSource MAC: ");

    for (i = 0; i < 6; ++i) {
        printf("%02x", eth_header->ether_shost[i]);
        if (i < 5) {
            printf(":");
        }
    }

    printf("\nDestination MAC: ");
    for (i = 0; i < 6; ++i) {
        printf("%02x", eth_header->ether_dhost[i]);
        if (i < 5) {
            printf(":");
        }
    }

    printf("\n");

    struct ip *IPHeader;

    struct tcphdr *TCPHeader;

    //IPv4 Packet.
    if (ntohs(eth_header->ether_type) == ETH_P_IP) {
        printf("============ IP HEADER ============\n");
        IPHeader = (struct ip *) data + ETH_HLEN; 
        const unsigned char *IPPayload = data + ETH_HLEN + (IPHeader->ip_hl*4);

        printf("IPv4 Packet \n");
        printf("IP Packet Length: %hu\n", IPHeader->ip_len);
        printf("IP Header Length (Bytes): %u\n", IPHeader->ip_hl*4);
        printf("IP Source: %u\n", ntohl(IPHeader->ip_src.s_addr));
        printf("Type of service: %hhu\n", IPHeader->ip_tos);
        printf("ID: %hu\n", ntohs(IPHeader->ip_id));
        printf("Fragment: %hu\n", ntohs(IPHeader->ip_off));
        printf("Time to live: %hhu\n", IPHeader->ip_ttl);
        printf("Protocol: %hhu\n", IPHeader->ip_p);
        
        //TCP Packet
        if (IPHeader->ip_p == IPPROTO_TCP) {
            printf("============ TCP HEADER ============\n");
            TCPHeader = (struct tcphdr *) IPPayload;

            printf("Source Port: %u\n", ntohs(TCPHeader->source));
            printf("Destination Port: %u\n", ntohs(TCPHeader->dest));
            printf("Seq Num: %lu\n", ntohl(TCPHeader->seq));
            printf("Ack Num: %lu\n", ntohl(TCPHeader->ack_seq));
            printf("Urgent Pointer: %u\n", ntohs(TCPHeader->urg_ptr));
            printf("Flags:\n");
            printf("URG|ACK|PSH|RST|SYN|FIN\n");
            printf("[%u]|[%u]|[%u]|[%u]|[%u]|[%u]\n",
                TCPHeader->urg, TCPHeader->ack, TCPHeader->psh,
                TCPHeader->rst, TCPHeader->syn, TCPHeader->fin);
        }
    }

    struct ether_arp *ether_arp = NULL;

    //ARP Packet
    if(ntohs(eth_header->ether_type) == ETH_P_ARP) {
        printf("============ ARP HEADER ============\n");

        //Like above, load the arp packet info into the ether_Arp struct, which starts after the ethernet header.
        ether_arp = (struct ether_arp*) (data + ETH_HLEN);

        printf("[ARP] Hardware type: %s\n", (ether_arp->ea_hdr.ar_hrd) == 1 ? "Ethernet" : "??"); 
        printf("[ARP] Protocol type is: %s\n", (ether_arp->ea_hdr.ar_pro) == 0x0800 ? "IPv4" : "??"); 
        printf("[ARP] Operation: %s\n", (ether_arp->ea_hdr.ar_op) == 1 ? "ARP Request" : "ARP Reply"); 
            
    }

    printf("\nType: %hu\n", eth_header->ether_type);
    printf(" === PACKET %ld DATA == \n", pcount);

    // Decode Packet Data (Skipping over the header)
    int data_bytes = length - ETH_HLEN;
    const unsigned char *payload = data + ETH_HLEN;
    const static int output_sz = 20; // Output this many bytes at a time
    while (data_bytes > 0) {
        int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
        // Print data in raw hexadecimal form
        for (i = 0; i < output_sz; ++i) {
            if (i < output_bytes) {
                printf("%02x ", payload[i]);
            } else {
                printf ("   "); // Maintain padding for partial lines
            }
        }
        printf ("| ");
        // Print data in ascii form
        for (i = 0; i < output_bytes; ++i) {
            char byte = payload[i];
            if (byte > 31 && byte < 127) {
                // Byte is in printable ascii range
                printf("%c", byte);
            } else {
                printf(".");
            }
        }

        printf("\n");
        payload += output_bytes;
        data_bytes -= output_bytes;
    }
    pcount++;
}
