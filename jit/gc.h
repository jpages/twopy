/*
    Garbage Collector header file
*/

void create_gc(char* beginning_address, char* end_address);

void gc_phase(uint64_t*, uint64_t*);
