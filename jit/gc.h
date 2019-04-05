/*
    Garbage Collector header file

    The current algorithm is a copying GC based on cheney's algorithm
*/

void create_gc(char* beginning_address, char* end_address);

uint64_t copy_root(uint64_t, char*);

void gc_phase(uint64_t*, uint64_t*, int);

