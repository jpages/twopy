#include "gc.h"


struct heap
{
    // Address of the beginning of the free space in the heap
    char* fromspace;

    // Address for the GC algorithm to copy objects
    char* tospace;
};

struct heap* myHeap;

// Create and initialize a new heap structure
void create_gc(char* beginning_address, char* end_address)
{
    // Initialize GC structures with the heap beginning and end
    if(myHeap == NULL)
    {
        printf("Begin %p\n", beginning_address);
        printf("end %p\n", end_address);

        // Create a new heap structure
        myHeap = (struct heap*) malloc(sizeof(struct heap*));
        myHeap->fromspace = beginning_address;
        myHeap->tospace = end_address;
    }
}

// Copy this object in a new space
uint64_t copy_root(uint64_t object, char** allocPtr)
{
    // TODO: forwarding addresses
    /*If o has no forwarding address
        o' = allocPtr
        allocPtr = allocPtr + size(o)
        copy the contents of o to o'
        forwarding-address(o) = o'
    EndIf
    return forwarding-address(o)*/

    // If o has no forwarding address
    char* new_object = *allocPtr;

    // Dereference the root to access its header and content
    uint64_t* untag_address = object >> 3;
    int size = untag_address[0] + 8;

    // Copy the header and the object to the new space
    memcpy(new_object, untag_address, size);
    *allocPtr = *allocPtr + size;

    // Put the forwarding pointer in the old position of this object
    untag_address[0] = new_object;

    // Return the new position, with a tag
    uint64_t new_address = ((uint64_t)new_object)<<3;
    return new_address;
}

// Launch a gc phase
void gc_phase(uint64_t* rsp, uint64_t* register_allocation, int stack_size)
{
    printf("fromspace %p\n", myHeap->fromspace);
    printf("tospace %p\n", myHeap->tospace);

//    printf("Current allocation register %p\n", register_allocation);

    // Swap semi spaces
    char *tmp = myHeap->fromspace;
    myHeap->fromspace = myHeap->tospace;
    myHeap->tospace = tmp;

    // Use these two pointers to scan the heap
    char* allocPtr = myHeap->fromspace;
    char* scanPtr  = myHeap->fromspace;

    // Allocate some size for roots
    uint64_t roots[stack_size];
    int index = 0;

    // Scan every root in the stack
    for(int i=0; i<stack_size; i++)
    {
        // extract the tag
        int tag = (int)rsp[i] & 7;

        // All possibilities for boxed types in Twopy
        if(tag == 4 || tag == 5 || tag == 6)
        {
            roots[index++] = rsp[i];

            // Copy this root to the new space
            roots[index] = copy_root(roots[index], &allocPtr);
            rsp[i] = roots[index];
        }
    }

    printf("AllocPtr before the loop %p\n", allocPtr);

    while(scanPtr < allocPtr)
    {
        char* object = scanPtr;
        //int tag = (int)rsp[i] & 7;
        printf("ScanPtr %p\n", scanPtr);
        printf("size in object %d\n", object[0]);
        scanPtr = scanPtr + (int)object[8] + 8;

    }
//    -- scan objects in the heap (including objects added by this loop)
//    While scanPtr < allocPtr
//        ForEach reference r from o (pointed to by scanPtr)
//            r = copy(r)
//        EndForEach
//        scanPtr = scanPtr  + o.size() -- points to the next object in the heap, if any
//    EndWhilel,;n

    asm("INT3");
    // TODO: change the value of the allocation register to the other space
}


