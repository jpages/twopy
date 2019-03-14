#include "gc.h"


//struct heap
//{
//    // Address of the beginning of the heap
//    char* begin;
//
//    // End address
//    char* end;
//}


//struct heap myHeap;

/* GC part */
void test_gc()
{
    printf("We are in the GC\n");
}

void create_gc(char* beginning_address, char* end_address)
{
    // Initialize GC structures with the heap beginning and end
    printf("Beginning %p\n", beginning_address);
    printf("End %p\n", end_address);
}
