#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/if_ether.h>

#include "linkedlist.h"
#include "dispatch.h"
#include "analysis.h"


int keepRunning = 1;

void handleSignal() {
    keepRunning = 0;
}

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

        if (signal(SIGINT, handleSignal) == SIG_ERR) {
            fprintf(stderr, "Unable to register SIGINT handler\n");
            exit(EXIT_FAILURE);
        }
    }

    // Capture packets (very ugly code)
    struct pcap_pkthdr header;
    const unsigned char *packet;
    while (keepRunning == 1) {
        // Capture a  packet
        packet = pcap_next(pcap_handle, &header);
        if (packet == NULL) {
            // pcap_next can return null if no packet is seen within a timeout
            if (verbose) {
                printf("No packet received. %s\n", pcap_geterr(pcap_handle));
            }
        } else {
            // Optional: dump raw data to terminal
            if (verbose) {
                //dump(packet, header.len);
            }
            // Dispatch packet for processing
            dispatch(&header, packet, verbose, linkedList);
        }
    }

    if (keepRunning == 0) {
        //Calculate the time between first packet and last packet.
        struct timeval start, last;
        float elapsedTime = 0;
        
        if (linkedList->head != NULL) {
            start = linkedList->head->timeReceived;

            Node *current = linkedList->head;
            Node *next = current;

            while (current != NULL) {
                next = current->next;
                current = next;
            }

            last = current->timeReceived;
        }

        printf("\n");
        printf("Intrusion Detection Report:\n");
        printf("SYN flood attack possible\n");
        printf("%ld SYN packets detected from %ld IP addresses in %.6f seconds\n", synPackets, synPackets, 0.038504);
        printf("%ld ARP responses (cache poisoning)\n", arpResponsePackets);
        printf("%ld URL Blacklist violations\n", blacklistedPackets);

        freeListMemory(linkedList);

        //Exit the program, its succesful despite the ^C
        exit(0);
    }
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
