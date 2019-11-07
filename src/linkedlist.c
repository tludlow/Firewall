#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include "linkedlist.h"

/**
* Structs
*/

struct node {
    struct timeval timeReceived; //https://pubs.opengroup.org/onlinepubs/007908799/xsh/systime.h.html <- timeval documentation
    long sourceIP; //The source ip of the packet.

    struct Node *next;
};

//List struct, holds the header node and makes the syntax of using the linked list nicer.
struct list {
    Node *head; 
};


/**
*  Node/List functions.
*/

//Create a new node for the list, we dont need to define the time received its assumed to be when we are creating the node.
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

//Microseconds between first packet and last packet.
float getElapsedTime(List *list) {
    //No point computing the time in this case, nothing happened.
    if(list->head == NULL || list->head->next == NULL) {
        return 0;
    }

    Node *head = list->head;
    Node *current = list->head;
    Node *next = current;

    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }

    return (float)(current->timeReceived.tv_sec - head->timeReceived.tv_sec);
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