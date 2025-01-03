/* ********************************
 * Author:       Thomas Ludlow - u1814232
 * Description:  A linked list implementation in C, used to store IP addresses and the time received of the packet which the IP was in.
 *
 *//** @file linkedlist.h *//*
 *
 ********************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include "linkedlist.h"

/*  Struct: node
 *  An individual element of a linked list, pointing to the next node (singly linked list) and storing data about the packet.
 */
struct node {
    struct timeval timeReceived; //https://pubs.opengroup.org/onlinepubs/007908799/xsh/systime.h.html <- timeval documentation
    long sourceIP; //The source ip of the packet.

    struct Node *next;
};

/*  Struct: list
 *  A list struct which holds the head node, makes the code look nicer throughout rather than just referencing a head node instead of a list everytime.
 */
struct list {
    Node *head;
};


/**
*  Node/List functions.
*/

//Creates a new node and return the pointer.
Node *createNode(long sourceIP) {
    Node *newNode = malloc(sizeof(Node));

    if (!newNode) {
        return NULL;
    }

    gettimeofday(&(newNode->timeReceived), NULL);
    newNode->sourceIP = sourceIP;
    newNode->next = NULL;

    return newNode;
}

//Create a new empty list.
List *createList() {
    List *list = malloc(sizeof(List));

    if (!list) {
        return NULL;
    }

    list->head = NULL;
    return list;
}

//Add a node to a list. Will only add if the packet is unique.
void add(List *list, long sourceIP) {
    Node *current = NULL;

    if (list->head == NULL) {
        //Cant be non unique, its the only thing in the list.
        list->head = createNode(sourceIP);
    } else {
        current = list->head;

        while (current->next != NULL) {
            current = current->next;

            if (current->sourceIP == sourceIP) {
                //Is non unique, we dont need to add..
                return;
            }
        }
        current->next = createNode(sourceIP);
    }
}

//Adds to the linked list only if the IP address provided isnt already in the linked list.
void addUnique(List *list, long sourceIP, struct timeval timeReceived) {
    Node *current = NULL;

    Node *newNode = malloc(sizeof(Node));

    if (!newNode) {
        return NULL;
    }

    newNode->timeReceived = timeReceived;
    newNode->sourceIP = sourceIP;
    newNode->next = NULL;
    
    if(isUnique(list, sourceIP) == 0) {
        //This source ip is not unique, we dont need to do anything.
        return;
    }

    if (list->head == NULL) {
        //Cant be non unique, its the only thing in the list.
        list->head = newNode;
    } else {
        current = list->head;

        while (current->next != NULL) {
            current = current->next;

            if (current->sourceIP == sourceIP) {
                //Is non unique, we dont need to add..
                return;
            }
        }

        current->next = newNode;
    }
}

//Microseconds between first packet and last packet.
//Doesnt need mutex to be used on this, only ever ran by single thread on termination.
float getElapsedTime(List *list) {
    if (list->head == NULL) {
        return 0;
    }

    List *uniqueList = createList();
    int packetsReceived = 0;

    Node *current = list->head;

    for (; current != NULL; current = current->next) {
        addUnique(uniqueList, current->sourceIP, current->timeReceived);
        packetsReceived++;
    }

    Node *firstNode = list->head;

    //Get to the last node of the list.
    Node *currentCheck = list->head;
    while(currentCheck->next != NULL) {
        currentCheck = currentCheck->next;
    }

    Node *lastNode = currentCheck;

    struct timeval firstTime = firstNode->timeReceived;
    struct timeval lastTime = lastNode->timeReceived;

    double timeElapsedSeconds = (((lastTime.tv_sec - firstTime.tv_sec) * 1000000) + (lastTime.tv_usec - firstTime.tv_usec)) * 0.000001;

    //printf("Ran elapsed time, got %f seconds\n", timeElapsedSeconds);
    return timeElapsedSeconds;
}

//1 if possible attack,  0 for no attack.
//Doesnt need mutex to be used on this, only ever ran by single thread on termination.
int isPossibleAttack(List *list) {
    if (list->head == NULL) {
        return 0;
    }

    List *uniqueList = createList();
    int packetsReceived = 0;

    Node *current = list->head;

    for (; current != NULL; current = current->next) {
        addUnique(uniqueList, current->sourceIP, current->timeReceived);
        packetsReceived++;
    }

    int uniqueCounter = 0;
    Node *currentUnique = uniqueList->head;

    for (; currentUnique != NULL; currentUnique = currentUnique->next) {
        uniqueCounter++;
    }

    float nintyPercent = (uniqueCounter * 100) / packetsReceived;

    if (nintyPercent >= 90) {
        float timeDiff = getElapsedTime(list);

        float rate = (float)uniqueCounter / timeDiff;
        //printf("Ran possible attack, found the percent of %f and the rate of %f\n", nintyPercent, rate);
        if(rate > 100) {
            return 1;
        }

    }
    return 0;
}

//Returns the number of unique IP's in the list.
//Doesnt need mutex to be used on this, only ever ran by single thread on termination.
int uniqueIPS(List *list) {
    if (list->head == NULL) {
        return 0;
    }

    List *uniqueList = createList();
    int packetsReceived = 0;

    Node *current = list->head;

    for (; current != NULL; current = current->next) {
        addUnique(uniqueList, current->sourceIP, current->timeReceived);
        packetsReceived++;
    }

    int uniqueCounter = 0;
    Node *currentUnique = uniqueList->head;

    for (; currentUnique != NULL; currentUnique = currentUnique->next) {
        uniqueCounter++;
    }

    //printf("Ran unique ids, found %d unique ip addresses\n", uniqueCounter);
    return uniqueCounter;
}

//Determines whether or not an IP is unique.
//1 = unique, 0 = not unique
int isUnique(List *list, long sourceIP) {
    //Go through the list and make sure the source ip provided is unique across all nodes.
    Node *current = list->head;
    int unique = 1;

    if(list->head == NULL) {
        return 1;
    }

    for (; current != NULL; current = current->next) {
        if (current->sourceIP == sourceIP) {
            unique = 0;
            break;
        }
    }

    return unique;
}

//Free the memory of the list, this includes the nodes too
void freeListMemory(List *list) {
    Node *current = list->head;
    Node *next = current;

    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }

    free(list);
}

//Printing the list will be useful for debugging whats contained within this lsit.
void printList(List *list) {
    Node *current = list->head;

    if(list->head == NULL) {
        printf("[EMPTY LIST]");
    }

    for (; current != NULL; current = current->next) {
        printf("[%ld, %d]->", current->sourceIP, current->timeReceived.tv_usec);
    }

    printf("\n");
}
