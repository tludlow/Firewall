#include "dispatch.h"
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <pcap.h>

#include "analysis.h"
#include "linkedlist.h"
#include "queue.h"

#define MAX_THREADS 4
int keepRunning = 1; //Whether or not we have received the Ctrl+C signal.

Queue *staticQueue; //Queue holding the packets yet to process

pthread_mutex_t queuePacketLock = PTHREAD_MUTEX_INITIALIZER; //Queue mutex

pthread_t threads[MAX_THREADS]; //Thread pool, the storage of the threads


void createThreadPool(List *list) {
    staticQueue = createQueue();

    //Make the threads and store thme in the pool (threads array)
    int threadCount = 0;
    printf("Creating %d threads.\n", MAX_THREADS);
    for (threadCount = 0;  threadCount < MAX_THREADS; threadCount++) {
        pthread_create(&threads[threadCount], NULL, &threadProgram, list);
    }
    
}

void handleSignal(int signal) {
    if(signal == SIGINT) {
        keepRunning = 0;
    }
}

struct dispatchArgs {
    int verbose;
    List *linkedList;
};


void dispatch(u_char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    struct dispatchArgs *dArgs = args;
    if (signal(SIGINT, handleSignal) == SIG_ERR) {
        fprintf(stderr, "Ctrl-C closing has caused an error...\n");
        exit(EXIT_FAILURE);
    }

    if (keepRunning == 0) {
        //Kill of all our threads.
        void *threadReturnPoint;
        int threadCount = 0;
        for (threadCount = 0;  threadCount < MAX_THREADS; threadCount++) {
           pthread_join(threads[threadCount], &threadReturnPoint);
        }

        //All threads are now dead, we can now make the report.

        //Unique IPS that sent SYN attack packets.
        int unique = uniqueIPS(dArgs->linkedList);

        //The time between the first syn attack packet and the last
        float elapsed = getElapsedTime(dArgs->linkedList);

        printf("\n");
        printf("Intrusion Detection Report:\n");
        if (isPossibleAttack(dArgs->linkedList) == 1) {
            printf("SYN flood attack possible\n");
        }
        printf("%ld SYN packets detected from %ld IP addresses in %.6f seconds\n", synPackets, unique, elapsed);
        printf("%ld ARP responses (cache poisoning)\n", arpResponsePackets);
        printf("%ld URL Blacklist violations\n", blacklistedPackets);

        freeListMemory(dArgs->linkedList);

        //Exit the program, its succesful despite the ^C
        exit(0);
    }

    //We are going to either analyse (if were running in verbose) or add the packet to the queue for the threads to handle.
    if (dArgs->verbose) {
        dump(packet, header->len);
        analyse(header, packet, dArgs->linkedList);
    } else {
        //Add the packet to the queue, the threads will read from this and call analyse themselves.
        //Lock the thread so that we can write to it without issues happening.
        pthread_mutex_lock(&queuePacketLock);
        enqueue(staticQueue, packet);
        pthread_mutex_unlock(&queuePacketLock);
    }
}

//Function ran by the thread itself.
void *threadProgram(void *threadArg) {
    //Signal checker.
    signal(SIGINT, handleSignal);

    if (keepRunning == 0) {
        free(threadArg);
    }

    while(keepRunning == 1) {
        //Try and pop from the queue, lock and unlock to prevent data issues
        pthread_mutex_lock(&queuePacketLock);
        unsigned char *packet = dequeue(staticQueue);
        pthread_mutex_unlock(&queuePacketLock);

        if (packet != NULL) {
            analyse(NULL, packet, threadArg);
        }
    }
}
