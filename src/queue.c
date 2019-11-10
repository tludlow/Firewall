#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

struct queueNode {
    unsigned char *packet;
    struct Node *next;
};

struct queue {
    QueueNode *front;
    QueueNode *back;
    int length;
};


//Create a new node for the queue
QueueNode *createNodeQueue(unsigned char *packet) {
    QueueNode *newNode = malloc(sizeof(QueueNode));

    if (!newNode) {
        return NULL;
    }

    newNode->packet = packet;
    newNode->next = NULL;

    return newNode;
}

//Create an empty queue.
Queue *createQueue() {
    Queue *queue = malloc(sizeof(Queue));

    if (!queue) {
        return NULL;
    }

    queue->front = NULL;
    queue->back = NULL;
    queue->length = 0;

    return queue;
}

void addQueueNode(Queue *queue, unsigned char *packet) {
    QueueNode *current = NULL;

    if (queue->front == NULL) {
        //Queue is empty, we must make the front and the back equal to eachother.
        queue->front = createNodeQueue(packet);
        queue->back = queue->front;
        queue->length = 1;
    } else {
        current = queue->front; 

        while (current->next != NULL) {
            current = current->next;
        }

        current->next = createNodeQueue(packet);
        queue->back = current->next;
        queue->length = queue->length + 1;
    }
}

void freeQueueMemory(Queue *queue) {
    QueueNode *current = queue->front;
    QueueNode *next = current;

    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }

    free(queue);
}


void printQueue(Queue *queue) {
    QueueNode *current = queue->front;

    if(queue->front == NULL) {
        printf("[EMPTY QUEUE]\n");
        return;
    }

    if (queue->front != NULL) {
        printf("[SIZE = %d] {FRONT = %u}   ", queue->length, queue->front->packet);
    }
    if(queue->back != NULL) {
        printf("{BACK = %u}   ||  ", queue->back->packet);
    }

    for (; current != NULL; current = current->next) {
        printf("[%u]->", current->packet);
    }
}

unsigned char * dequeue(Queue *queue) {
    if (queue->front == NULL) {
        return NULL;
    }

    //Store the current head, rewrite the queue and then return the stored head.
    QueueNode *storedFront = queue->front;

    if(queue->front->next != NULL) {
        queue->front = queue->front->next;
        queue->length = queue->length - 1;
    } else {
        queue->front = NULL;
    }
    
    return storedFront->packet;

}

void enqueue(Queue *queue, unsigned char *packet) {
    addQueueNode(queue, packet);
}
