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
            printf("RSP %ld\\n", *rsp);
            printf("Code %ld\\n", *code);

            printf("Code adress %p\\n", code);
            printf("RSP adress %p\\n", rsp);
            *rsp = code;

            printf("RSP adress %ld\\n", *rsp);

            printf("COUCOU\\n");
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
    # stub_id : The id the identifier of the block
    def compile_stub(self, code, stub_id):

        stub_label = asm.Label("Stub_label_"+str(stub_id))

        code.add_instruction(asm.JMP(stub_label))
        code.add_instruction(asm.LABEL(stub_label))

        # Calling convention of x86_64 for Unix platforms here
        code.add_instruction(asm.MOV(asm.rdi, stub_id))

        # Now we store the stack pointer to patch it later
        code.add_instruction(asm.MOV(asm.rsi, asm.registers.rsp))

        reg_id = asm.r15

        function_address = int(ffi.cast("intptr_t", ffi.addressof(lib, "stub_function")))
        code.add_instruction(asm.MOV(reg_id, function_address))

        code.add_instruction(asm.CALL(reg_id))


# This function is called when a stub is executed, we must compile the appropriate block and replace some code
# stub_id : The identifier of the basic block to compile
@ffi.callback("void(uint64_t, int*)")
def python_callback_stub(stub_id, rsp):

    # We must now trigger the compilation of the corresponding block
    block = jitcompiler_instance.stub_dictionary[stub_id]

    peachpy_function = jitcompiler_instance.dict_functions[block.function]
    array = jitcompiler_instance.compile_instructions(peachpy_function, block, block.function.allocations)

    c_buffer = ffi.from_buffer(array)
    lib.patch_rsp(rsp, c_buffer)


lib.python_callback_stub = python_callback_stub
