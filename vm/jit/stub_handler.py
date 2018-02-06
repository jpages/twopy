# coding=utf-8
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
        // The function called by the assembly jited code to compile a given basic block
        void bb_stub(uint64_t id_stub, uint64_t* rsp);

        // Stub for a function compilation
        void function_stub(int nbargs, uint64_t name_id, uint64_t code_id, uint64_t* rsp, uint64_t address_after);

        // Python function callback
        extern "Python" uint64_t* python_callback_bb_stub(uint64_t stub_id, uint64_t* rsp);
        
        // Callback to trigger the compilation of a function
        extern "Python" uint64_t python_callback_function_stub(uint64_t, uint64_t);

        // Print the stack from the stack pointer in parameter
        void print_stack(uint64_t* rsp);

        // Print the array from the pointer in parameter
        void print_data_section(uint64_t* array, int size);

        // Get the address of an element in a bytearray
        uint64_t get_address(char* bytearray, int index);
        
        // twopy lib
        void twopy_library_print_integer(int);
    """)

# C Sources
ffi.set_source("stub_module", """
        #include <stdio.h>
        #include <stdlib.h>

        // Function called to handle the compilation of stubs for basic blocks
        static uint64_t* python_callback_bb_stub(uint64_t stub_id, uint64_t* rsp);
        
        static uint64_t python_callback_function_stub(uint64_t, uint64_t);

        void bb_stub(uint64_t id_stub, uint64_t* rsp_value)
        {
            uint64_t* rsp_address_patched = python_callback_bb_stub(id_stub, rsp_value);

            // Patch the return address to jump on the newly compiled block
            rsp_value[-1] = (long long int)rsp_address_patched;
        }

        // Handle the compilation of a function's stub
        void function_stub(int nbargs, uint64_t name_id, uint64_t code_id, uint64_t* rsp, uint64_t address_after)
        {
            // Callback to python to trigger the compilation of the function
            uint64_t* function_address = (uint64_t*)python_callback_function_stub(name_id, code_id);
               
            rsp = rsp + 1;
            
            // Put on the stack the address of the next function   
            rsp[-1] = (long long int)function_address;

            // Patch the return address
            rsp[-2] = (long long int)address_after;
            
        }

        void print_stack(uint64_t* rsp)
        {
            printf("Print the stack\\n");
            for(int i=-5; i!=5; i++)
                printf("\\t %ld stack[%d] = 0x%lx\\n", (long int)&rsp[i], i, rsp[i]);
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
        void twopy_library_print_integer(int toprint)
        {
            printf("We are here\\n");
            printf("%d\\n", toprint);
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
    def compile_stub(self, mfunction, stub_id):

        # The call to that will be compiled after the stub compilation is over
        # Put a NOP instruction for now to get the offset
        address = mfunction.allocator.encode_stub(asm.NOP())

        # Calling convention of x86_64 for Unix platforms here
        mfunction.allocator.encode_stub(asm.MOV(asm.rdi, stub_id))

        # Now we store the stack pointer to patch it later
        mfunction.allocator.encode_stub(asm.MOV(asm.rsi, asm.registers.rsp))

        reg_id = asm.r10

        function_address = int(ffi.cast("intptr_t", ffi.addressof(lib, "bb_stub")))
        mfunction.allocator.encode_stub(asm.MOV(reg_id, function_address))

        mfunction.allocator.encode_stub(asm.CALL(reg_id))

        return address

    # Compile a stub to a function
    # mfunction: The simple_interpreter.Function
    # nbargs : number of arguments in the registers, used by C function later
    # address_after : where to jump after the stub
    def compile_function_stub(self, mfunction, nargs, address_after):
        stub_label = asm.Label("Stub_label_" + str(mfunction.name))

        # The call to that will be compiled after the stub compilation is over
        address = mfunction.allocator.encode_stub(asm.LABEL(stub_label))

        # Save the RSP to patch it after
        mfunction.allocator.encode_stub(asm.MOV(asm.rcx, asm.registers.rsp))
        mfunction.allocator.encode_stub(asm.MOV(asm.r8, address_after))


        # Call the stub function in C
        function_address = int(ffi.cast("intptr_t", ffi.addressof(lib, "function_stub")))
        mfunction.allocator.encode_stub(asm.MOV(asm.r10, function_address))
        mfunction.allocator.encode_stub(asm.CALL(asm.r10))

        return address

# This function is called when a stub is executed, we must compile the appropriate block and replace some code
# stub_id : The identifier of the basic block to compile
@ffi.def_extern()
def python_callback_bb_stub(stub_id, rsp):

    # We must now trigger the compilation of the corresponding block
    stub = jitcompiler_instance.stub_dictionary[stub_id]

    # Delete the entry
    del jitcompiler_instance.stub_dictionary[stub_id]

    # Get the offset of the first instruction compiled in the block
    first_offset = jitcompiler_instance.compile_instructions(stub.block.function, stub.block)

    # Patch the old code to not jump again in the stub
    stub.patch_instruction(first_offset)

    if jitcompiler_instance.interpreter.args.verbose:
        stub.block.function.allocator.disassemble_asm()

    # The new value of the RSP
    c_buffer = ffi.from_buffer(stub.block.function.allocator.code_section)
    rsp_address_patched = lib.get_address(c_buffer, first_offset)

    return ffi.cast("uint64_t*", rsp_address_patched)


# This function is called when a stub is executed, need to compile a function
@ffi.def_extern()
def python_callback_function_stub(name_id, code_id):
    # Generate the Function object in the model
    name = jitcompiler_instance.consts[name_id]
    code = jitcompiler_instance.consts[code_id]

    function = jitcompiler_instance.interpreter.generate_function(code, name, jitcompiler_instance.interpreter.mainmodule, False)

    # Trigger the compilation of the given function
    jitcompiler_instance.compile_function(function)

    if jitcompiler_instance.interpreter.args.verbose:
        function.allocator.disassemble_asm()

    return function.allocator.code_address

# Used to patch the code after the compilation of a stub
class Stub:
    # block : The BasicBlock compiled by this stub
    # instruction : The peachpy assembly instruction which jump to the stub
    # position : position of this instruction in the code segment (offset of the beginning)
    def __init__(self, block, instruction, position):
        self.block = block
        self.instruction = instruction
        self.position = position

    # Patch the instruction after the stub compilation
    # first_offset : offset of the first instruction newly compiled in the block
    def patch_instruction(self, first_offset):

        if isinstance(self.instruction, asm.MOV):
            # Moving an address inside a register, we need to change the address here

            new_address = lib.get_address(ffi.from_buffer(self.block.function.allocator.code_section), first_offset)
            new_instruction = asm.MOV(self.instruction.operands[0], new_address)

            # Create the new encoded instruction and replace the old one in the code section
            encoded = new_instruction.encode()
            self.block.function.allocator.write_instruction(encoded, self.position)

            # TODO: optimize this by not jumping if we are supposed to jump to the next instruction
        elif isinstance(self.instruction, asm.JGE):
            new_operand = first_offset - self.position - 2

            # Update to the new position
            new_instruction = asm.JGE(asm.operand.RIPRelativeOffset(new_operand))
            encoded = new_instruction.encode()

            # If the previous instruction was a 32 bits offset, force it to the new one
            if len(self.instruction.encode()) > 2:
                encoded = bytearray(3)

                # We use 4 more bytes for the encoding compare to the 8 bits version
                new_operand = new_operand - 4

                # Force the 32 encoding of the JGE
                encoded[0] = 0x0F
                encoded[1] = 0x8D

                # Keep the same value for the jump
                encoded[2] = new_operand

            self.block.function.allocator.write_instruction(encoded, self.position)
        elif isinstance(self.instruction, asm.JG):

            new_operand = first_offset - self.position - len(self.instruction.encode())

            # Update to the new position
            new_instruction = asm.JG(asm.operand.RIPRelativeOffset(new_operand))
            encoded = new_instruction.encode()

            # If the previous instruction was a 32 bits offset, force it to the new one
            if len(self.instruction.encode()) > 2:
                encoded = bytearray(len(self.instruction.encode()))

                # Force the 32 encoding of the JG instruction
                encoded[0] = 0x0F
                encoded[1] = 0x8F
                encoded[2] = 0
                encoded[3] = 0
                encoded[4] = 0
                encoded[5] = 0

                size = math.ceil(new_operand / 256)
                bytes = new_operand.to_bytes(size, 'big')

                for i in range(0, len(bytes)):
                    encoded[i+2] = bytes[i]

            self.block.function.allocator.write_instruction(encoded, self.position)
        elif isinstance(self.instruction, asm.JL):
            new_operand = first_offset - self.position - len(self.instruction.encode())

            # Update to the new position
            new_instruction = asm.JL(asm.operand.RIPRelativeOffset(new_operand))
            encoded = new_instruction.encode()

            # If the previous instruction was a 32 bits offset, force it to the new one
            if len(self.instruction.encode()) > 2:
                encoded = bytearray(len(self.instruction.encode()))

                # Force the 32 encoding of the JL instruction
                encoded[0] = 0x0F
                encoded[1] = 0x8C
                encoded[2] = 0
                encoded[3] = 0
                encoded[4] = 0
                encoded[5] = 0

                size = custom_ceil(new_operand / 256)
                bytes = new_operand.to_bytes(size, 'big')

                for i in range(0, len(bytes)):
                    encoded[i + 2] = bytes[i]

            self.block.function.allocator.write_instruction(encoded, self.position)
        else:
            print("Not yet implemented patch")

    def __str__(self):
        return "(Block = " + str(id(self.block)) + " instruction " + str(self.instruction) + " position " + str(self.position) + ")"

# Ceil without using the math library
def custom_ceil(n):
    res = int(n)
    return res if res == n or n < 0 else res+1


# Dictionnary between names and primitive function addresses
primitive_addresses = {
"abs" : abs,
"dict" : dict,
"help" : help,
"min" : min,
"setattr" : setattr,
"all" : all,
"dir" : dir,
"hex" : hex,
"next" : next,
"slice" : slice,
"any" : any,
"divmod" : divmod,
"id" : id,
"object" : object,
"sorted" : sorted,
"ascii" : ascii,
"enumerate" : enumerate,
"input" : input,
"oct" : oct,
"staticmethod" : staticmethod,
"bin" : bin,
"eval" : eval,
"int" : int,
"open" : open,
"str" : str,
"bool" : bool,
"exec" : exec,
"isinstance" : isinstance,
"ord" : ord,
"sum" : sum,
"bytearray" : bytearray,
"filter" : filter,
"issubclass" : issubclass,
"pow" : pow,
"super" : super,
"bytes" : bytes,
"float" : float,
"iter" : iter,
"print" : int(ffi.cast("intptr_t", ffi.addressof(lib, "twopy_library_print_integer"))),
"tuple" : tuple,
"callable" : callable,
"format" : format,
"len" : len,
"property" : property,
"type" : type,
"chr" : chr,
"frozenset" : frozenset,
"list" : list,
"range" : range,
"vars" : vars,
"classmethod" : classmethod,
"getattr" : getattr,
"locals" : locals,
"repr" : repr,
"zip" : zip,
"globals" : globals,
"map" : map,
"reversed" : reversed,
"__import__" : __import__,
"complex" : complex,
"hasattr" : hasattr,
"max" : max,
"round" : round,
"hash" : hash,
"delattr" : delattr,
"memoryview" : memoryview,
"set" : set,
}