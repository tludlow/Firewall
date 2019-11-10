#include "dispatch.h"
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <pcap.h>

#include "analysis.h"
#include "linkedlist.h"

#define MAX_THREADS 4

int keepRunning = 1;

pthread_rwlock_t readWriteLockPacket;
//Array of the threads we have.
pthread_t readThreads[MAX_THREADS];

void createThreadPool(void) {

    // pthread_rwlockattr_t *attr;
    // pthread_rwlockattr_init(&attr);
    // pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);

    // pthread_rwlock_init(&readWriteLockPacket, &attr);
    // pthread_rwlockattr_destroy(&attr);

    // //Make our threads.
    // int threadsCreated = 0;
    // for (i = 0; i < MAX_THREADS; i++) {
    //     pthread_create(&readThreads[i], NULL, &threadProgram, NULL);
    // }
}

void handleSignal(int signal) {
    if(signal == SIGINT) {
        keepRunning = 0;
    }
}


void dispatch(struct pcap_pkthdr *header, const unsigned char *packet, int verbose, List *linkedList) {
    // TODO: Your part 2 code here
    // This method should handle dispatching of work to threads. At present
    // it is a simple passthrough as this skeleton is single-threaded.

    if (signal(SIGINT, handleSignal) == SIG_ERR) {
        fprintf(stderr, "Ctrl-C closing has caused an error...\n");
        exit(EXIT_FAILURE);
    }

    if (keepRunning == 0) {
        //Calculate the time between first packet and last packet.
        float elapsedTime = getElapsedTime(linkedList);

        printf("\n");
        printf("Intrusion Detection Report:\n");
        printf("SYN flood attack possible\n");
        printf("%ld SYN packets detected from %ld IP addresses in %.6f seconds\n", synPackets, synPackets, elapsedTime);
        printf("%ld ARP responses (cache poisoning)\n", arpResponsePackets);
        printf("%ld URL Blacklist violations\n", blacklistedPackets);

        freeListMemory(linkedList);

        //Exit the program, its succesful despite the ^C
        exit(0);
    }

    analyse(header, packet, verbose, linkedList);
}

void *threadProgram(void *arg) {
    //Whether we are running in verbose mode...
    static const int verbose = 0;

    //The actual packet data to analyse.
    unsigned char *packetToAnalyse = NULL;

    //Signal checker.
    signal(SIGINT, handleSignal);

    //While the Ctrl-C command has not been pressed, run the thread.
    while (keepRunning != 0) {

        //If we actuallly have a packet, we should run it.
        if (packetToAnalyse != NULL) {
            analyse(NULL, packetToAnalyse, verbose, NULL);
        }
    }
}
