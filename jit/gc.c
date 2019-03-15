#include "gc.h"


struct heap
{
    // Address of the beginning of the heap
    char* begin;

    // End address
    char* end;
};

struct heap* myHeap;

// Create and initialize a new heap structure
void create_gc(char* beginning_address, char* end_address)
{
    // Initialize GC structures with the heap beginning and end
    if(myHeap == NULL)
    {
        // Create a new heap structure
        myHeap = (struct heap*) malloc(sizeof(struct heap*));
        myHeap->begin = beginning_address;
        myHeap->end = end_address;
    }
}
