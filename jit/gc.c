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

// Launch a gc phase
void gc_phase(uint64_t* rsp, uint64_t* register_allocation, int stack_size)
{
    printf("Begin %p\n", myHeap->begin);
    printf("end %p\n", myHeap->end);

    printf("RSP in gc_phase %p\n", rsp);
    printf("Current allocation register %p\n", register_allocation);

    printf("Stack_size in parameter %d\n", stack_size);

    collect_roots(rsp, stack_size);

    asm("INT3");
}

// Collect roots from the stack
void collect_roots(uint64_t* rsp, int stack_size)
{
    // Allocate some size for roots
    uint64_t roots[stack_size];
    int index = 0;

    for(int i=0; i<stack_size; i++)
    {
        // extract the tag
        int tag = (int)rsp[i] & 7;

        // All possibilities for boxed types in twopy
        if(tag == 4 || tag == 5 || tag == 6)
        {
            roots[index++] = rsp[i];
        }
    }

    for(int i=0; i<index; i++)
        printf("\tRoot %p \n", roots[i]);

}
