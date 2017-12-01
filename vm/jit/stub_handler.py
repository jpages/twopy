# Make the link between compiled assembly and high-level python functions
# Handle the compilation of stub functions
import cffi
import peachpy.x86_64 as asm


# Use the CFFI to define C functions which are callable from assembly
ffi = cffi.FFI()

# Define the stub_function and the callback for python
ffi.cdef("""
        uint64_t stub_function(uint64_t id_stub);

        // Python function callback
        void (*python_callback_stub)(uint64_t stub_id);
    """)

# C Sources
ffi.set_source("stub_module", """
        #include <stdio.h>
        
        // Function called to handle the compilation of 
        static void (*python_callback_stub)(uint64_t stub_id);

        uint64_t stub_function(uint64_t id_stub)
        {
            python_callback_stub(id_stub);
            return id_stub;
        }
    """)

# Now compile this and create python wrapper
ffi.compile()

# Import of the generated python module
from stub_module import ffi, lib

# Compile a call to a stub with an identifier
# code : The peachpy.Function
# stub_id : The id the identifier of the block
def compile_stub(code, stub_id):

    stub_label = asm.Label("Stub_label_"+str(stub_id))

    code.add_instruction(asm.JMP(stub_label))
    code.add_instruction(asm.LABEL(stub_label))

    # Calling convention of x86_64 for Unix platforms here
    code.add_instruction(asm.MOV(asm.rdi, stub_id))

    reg_id = asm.r15

    function_address = int(ffi.cast("intptr_t", ffi.addressof(lib, "stub_function")))
    code.add_instruction(asm.MOV(reg_id, function_address))
    code.add_instruction(asm.CALL(reg_id))

    #TODO: update the global dictionnary


# This function is called when a stub is executed, we must compile the appropriate block and replace some code
# stub_id : The identifier of the basic block to compile
@ffi.callback("void(uint64_t)")
def python_callback_stub(stub_id):
    print("Stub id from C " + str(stub_id))


lib.python_callback_stub = python_callback_stub
