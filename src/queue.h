#ifndef QUEUE_HEADER
#define QUEUE_HEADER

typedef struct queueNode QueueNode;
typedef struct queue Queue;


Queue *createQueue();
QueueNode *createNodeQueue(unsigned char *packet);
void addNode(Queue *queue, unsigned char *packet);
void printQueue(Queue *queue);
void freeQueueMemory(Queue *queue);

unsigned char * dequeue(Queue *queue);
void enqueue(Queue *queue, unsigned char *packet);

#endif