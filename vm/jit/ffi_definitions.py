# Contains all functions defined in C used by the standard library or the compiler to make callbacks to python

import cffi

# The following definitions must be top-level to facilitate the interface with C
# Use the CFFI to define C functions which are callable from assembly
ffi = cffi.FFI()

# Define the stub_function and the callback for python
ffi.cdef("""
        // The function called by the assembly jited code to compile a given basic block
        void bb_stub(uint64_t* rsp);

        // Stub for a function compilation
        void function_stub(uint64_t* rsp);

        // Stub for type-test
        void type_test_stub(uint64_t* rsp);
        
        // Stub for generating a class
        void class_stub(uint64_t* rsp);

        // Python function callback
        extern "Python+C" void python_callback_bb_stub(uint64_t rsp);

        // Callback to trigger the compilation of a function
        extern "Python+C" void python_callback_function_stub(uint64_t, uint64_t, uint64_t, uint64_t);

        // Callback for type tests
        extern "Python+C" void python_callback_type_stub(uint64_t, int, int);

        // Callback for class creation
        extern "Python+C" void python_callback_class_stub(uint64_t);

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

        // Print an error and exit
        void twopy_error(int);
    """)

c_code = """
        #include <stdio.h>
        #include <stdlib.h>

        // Function called to handle the compilation of stubs for basic blocks
        static void python_callback_bb_stub(uint64_t rsp);

        static void python_callback_function_stub(uint64_t, uint64_t, uint64_t, uint64_t);

        static void python_callback_type_stub(uint64_t, int, int);

        static void python_callback_class_stub(uint64_t);

        void bb_stub(uint64_t* rsp)
        {
            python_callback_bb_stub(rsp[-2]);
        }

        // Handle the compilation of a function's stub
        void function_stub(uint64_t* rsp)
        {
            uint64_t* code_address = (uint64_t*)rsp[-2];

            // Get the two values after the stub
            int nbargs = (int)code_address[0];
            uint64_t return_address = rsp[0];

            // Read values on the stack
            // For now consider we have just the name and code id
            long int name_id = rsp[1];
            long int code_id = rsp[2];

            //TODO: handle free variables list
            if(nbargs > 2)
                ;

            // Callback to python to trigger the compilation of the function
            python_callback_function_stub(name_id, code_id, return_address, rsp[3]);
        }

        // Handle compilation of a type-test stub
        void type_test_stub(uint64_t* rsp)
        {
            // Get the return address
            long int return_address = rsp[-2];

            long int return_address_aligned = return_address & -16;

            uint64_t* code_address = (uint64_t*)rsp[-2];

            int id_variable = (int)code_address[0];
            int type_value = (int)code_address[1];

            python_callback_type_stub(return_address_aligned, id_variable, type_value);
        }
        
        void class_stub(uint64_t* rsp)
        {
            python_callback_class_stub(rsp[-1]);
            asm("INT3");
        }

        void print_stack(uint64_t* rsp)
        {
            printf("Print the stack\\n");
            for(int i=-1; i!=7; i++)
                printf("\\t 0x%lx stack[%d] = 0x%lx\\n", (long int)&rsp[i], i, rsp[i]);
        }

        void print_data_section(uint64_t* array, int size)
        {
            printf("Print the array\\n");
            for(int i=0; i!=size; i++)
                printf("\\t %ld array[%d] = %ld\\n", (long int)&array[i], i, array[i]);
        }

        uint64_t get_address(char* bytearray, int index)
        {
            return (uint64_t)&bytearray[index];
        }

        // Print one integer on stdout
        int twopy_library_print_integer(long int value)
        {
            // Remove the integer tag for the print
            printf("%ld\\n", value/4);

            return value;
        }

        // Print the representation of a boolean        
        int twopy_library_print_boolean(int value)
        {
            // Remove the tag for the print
            if(value == 1)
                printf("False\\n");
            else
                printf("True\\n");    

            return value;
        }

        uint64_t twopy_library_print_string(uint64_t value)
        {
            // Remove the tag to get the address of the object
            uint64_t untag_address = value >> 2;

            // Get the size in the header
            int size = ((uint32_t*)untag_address)[0];

            // Create the pointer on the value
            char* chars_array = ((char*)untag_address + 32);

            // Print characters one by one, the UTF-8 encoding will be automatically displayed
            for(int i=0; i<size; i++)
                printf("%c", chars_array[i]);

            // Print a newline as requested by python
            printf("\\n");

            return value;
        }

        long int twopy_print(long int value)
        {
            // Test the tag of the object
            int tag = (int)value & 3;

            if(tag == 1)
                return twopy_library_print_boolean(value);
            else if(tag == 0)
                return twopy_library_print_integer(value);
            else if(tag == 3)
                return twopy_library_print_string(value);
            else
                printf("ERROR: unknown value %ld\\n", value);

            return value;
        }

        void twopy_error(int error_code)
        {
            if(error_code == 1)
                printf("ERROR: overflow \\n");
            else
                printf("ERROR: %d\\n", error_code);

            exit(-1);
        }
    """
# C Sources
ffi.set_source("stub_module", c_code)

# Now compile this and create python wrapper
ffi.compile()
