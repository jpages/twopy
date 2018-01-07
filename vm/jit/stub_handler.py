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
        // The function called by the assembly jited code
        void stub_function(uint64_t id_stub, uint64_t* rsp);

        // Python function callback
        extern "Python" uint64_t* python_callback_stub(uint64_t stub_id, uint64_t* rsp);
        
       extern "Python" uint64_t test_callback(uint64_t i);
    
        // Get the address of an element in a bytearray
        uint64_t get_address(char* bytearray, int index);
    """)

# C Sources
ffi.set_source("stub_module", """
        #include <stdio.h>

        // Function called to handle the compilation of 
        static uint64_t* python_callback_stub(uint64_t stub_id, uint64_t* rsp);
        
       static uint64_t test_callback(uint64_t i);

        void stub_function(uint64_t id_stub, uint64_t* rsp_value)
        {   
            printf("Un test \\n");
            test_callback(5);
            //uint64_t* rsp_address_patched = python_callback_stub(id_stub, rsp_value);
            //printf("Want to jump on %ld\\n", rsp_address_patched);
        
            // Patch the return address to jump on the newly compiled block
            //rsp_value[-1] = rsp_address_patched;
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
@ffi.def_extern()
def python_callback_stub(stub_id, rsp):

    print("Callback executed")
    # We must now trigger the compilation of the corresponding block
    block = jitcompiler_instance.stub_dictionary[stub_id]

    # Get the offset of the first instruction compiled in the block
    first_offset = jitcompiler_instance.compile_instructions(block.function, block)

    # TODO: disassemble asm here to test
    block.function.allocator.disassemble_asm()

    # The new value of the RSP
    c_buffer = ffi.from_buffer(block.function.allocator.code_section)
    rsp_address_patched = lib.get_address(c_buffer, first_offset)

    return ffi.cast("uint64_t*", rsp_address_patched)

@ffi.def_extern()
def test_callback(i):
    print(i)
    return i