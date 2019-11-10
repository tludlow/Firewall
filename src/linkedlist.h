#ifndef LINKEDLIST_HEADER
#define LINKEDLIST_HEADER

typedef struct node Node;
typedef struct list List;


List *createList();
Node *createNode(long sourceIP);


void add(List *list, long sourceIP);
void addNode(List *list, Node newNode);
void freeListMemory(List *list);
void printList(List *list);
int isUnique(List *list, long sourceIP);
int isPossibleAttack(List *list);
int uniqueIPS(List *list);

float getElapsedTime(List *list);

#endif