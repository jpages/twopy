# Make the link between compiled assembly and high-level python functions
# Handle the compilation of stub functions
import cffi
import peachpy.x86_64 as asm

from . import compiler

# The following definitions must be top-level to facilitate the interface with C
# Use the CFFI to define C functions which are callable from assembly
ffi = cffi.FFI()

# Define the stub_function and the callback for python
ffi.cdef("""
        uint64_t stub_function(uint64_t id_stub, int* rsp);
        void patch_rsp(int* rsp, char* code);

        // Python function callback
        void (*python_callback_stub)(uint64_t stub_id, int* rsp);
        
        // Get the address of an element in a bytearray
        uint64_t get_address(char* bytearray, int index);
    """)

# C Sources
ffi.set_source("stub_module", """
        #include <stdio.h>

        // Function called to handle the compilation of 
        static int* (*python_callback_stub)(uint64_t stub_id, int* rsp);

        uint64_t stub_function(uint64_t id_stub, int* rsp)
        {
            printf("RSP %ld\\n", *rsp);

            python_callback_stub(id_stub, rsp);

            return id_stub;
        }

        void patch_rsp(int* rsp, char* code)
        {
            *rsp = code;

            printf("RSP address %ld\\n", *rsp);
        }
        
        uint64_t get_address(char* bytearray, int index)
        {
            return (uint64_t)&bytearray[index];
        }
    """)

# Now compile this and create python wrapper
ffi.compile()

# Import of the generated python module
from stub_module import ffi, lib

# The instance of the JITCompiler, must be set somewhere else
jitcompiler_instance = None

stubhandler_instance = None


# Class for handle compilation of stubs, and ffi-related operations
class StubHandler:

    def __init__(self, jitcompiler):
        self.jitcompiler = jitcompiler

        global stubhandler_instance
        stubhandler_instance = self

    # Compile a call to a stub with an identifier
    # mfunction: The simple_interpreter.Function
    # stub_label : Label of the stub
    # stub_id : The id the identifier of the block
    def compile_stub(self, mfunction, stub_label, stub_id):

        stub_label = asm.Label("Stub_label_"+str(stub_id))

        # The call to that will be compiled after the stub compilation is over
        address = mfunction.allocator.encode_stub(asm.LABEL(stub_label))

        # Calling convention of x86_64 for Unix platforms here
        mfunction.allocator.encode_stub(asm.MOV(asm.rdi, stub_id))

        # Now we store the stack pointer to patch it later
        mfunction.allocator.encode_stub(asm.MOV(asm.rsi, asm.registers.rsp))

        reg_id = asm.r15

        function_address = int(ffi.cast("intptr_t", ffi.addressof(lib, "stub_function")))
        mfunction.allocator.encode_stub(asm.MOV(reg_id, function_address))

        mfunction.allocator.encode_stub(asm.CALL(reg_id))

        return address

# This function is called when a stub is executed, we must compile the appropriate block and replace some code
# stub_id : The identifier of the basic block to compile
@ffi.callback("void(uint64_t, int*)")
def python_callback_stub(stub_id, rsp):

    # We must now trigger the compilation of the corresponding block
    block = jitcompiler_instance.stub_dictionary[stub_id]


    array = jitcompiler_instance.compile_instructions(block.function, block)

    c_buffer = ffi.from_buffer(array)
    lib.patch_rsp(rsp, c_buffer)


lib.python_callback_stub = python_callback_stub
