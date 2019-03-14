/* This file contains all declarations for cffi.cdef */

// The function called by the assembly jited code to compile a given basic block
void bb_stub(uint64_t* rsp);

// Stub for a function compilation
void function_stub(uint64_t* rsp);

// Stub for type-test
void type_test_stub(uint64_t* rsp);

// Stub for generating a class
void class_stub(uint64_t* rsp);

// Allocate the code section with mmap and return a pointer to it
char* allocate_code_section(int);

// Allocate data section and return a pointer to it
char* allocate_data_section(int);

// Execute the allocated JIT code
void execute_code(char*);

// Python function callback
extern "Python+C" void python_callback_bb_stub(uint64_t rsp);

// Callback to trigger the compilation of a function
extern "Python+C" void python_callback_function_stub(uint64_t, uint64_t, uint64_t, uint64_t);

// Callback for type tests
extern "Python+C" void python_callback_type_stub(uint64_t, int, int);

// Callback for class creation
extern "Python+C" void python_callback_class_stub(uint64_t, uint64_t);

// Print the stack from the stack pointer in parameter
void print_stack(uint64_t* rsp);

// Print the array from the pointer in parameter
void print_data_section(uint64_t* array, int size);

// Get the address of an element in a bytearray
uint64_t get_address(char* bytearray, int index);

// Twopy general print
long int twopy_print(long int);

// twopy lib, print one integer
int twopy_library_print_integer(int);

// twopy lib, print one boolean
int twopy_library_print_boolean(int);

// twopy print, print a string encoded in unicode
uint64_t twopy_library_print_string(uint64_t);

// twopy print, default print method for an object
uint64_t twopy_library_print_object(uint64_t);

// twopy print, default print method for a float
uint64_t twopy_library_print_float(uint64_t);

// Print an error and exit
void twopy_error(int);
