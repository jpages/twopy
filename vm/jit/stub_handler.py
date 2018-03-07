# coding=utf-8
# Make the link between compiled assembly and high-level python functions
# Handle the compilation of stub functions
import cffi
import peachpy.x86_64 as asm
from . import objects

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

        // Python function callback
        extern "Python+C" uint64_t* python_callback_bb_stub(uint64_t stub_id, uint64_t* rsp);
        
        // Callback to trigger the compilation of a function
        extern "Python+C" uint64_t python_callback_function_stub(uint64_t, uint64_t);

        // Callback for type tests
        extern "Python+C" uint64_t python_callback_type_stub(uint64_t, int, int);

        // Print the stack from the stack pointer in parameter
        void print_stack(uint64_t* rsp);

        // Print the array from the pointer in parameter
        void print_data_section(uint64_t* array, int size);

        // Get the address of an element in a bytearray
        uint64_t get_address(char* bytearray, int index);
        
        // twopy lib, print one integer
        int twopy_library_print_integer(int);
    """)

c_code = """
        #include <stdio.h>
        #include <stdlib.h>
        #include <Python.h>

        // Function called to handle the compilation of stubs for basic blocks
        static uint64_t* python_callback_bb_stub(uint64_t stub_id, uint64_t* rsp);
        
        static uint64_t python_callback_function_stub(uint64_t, uint64_t);
        
        static uint64_t python_callback_type_stub(uint64_t, int, int);

        void bb_stub(uint64_t* rsp)
        {   
            // Read values after the stub
            uint64_t* code_address = (uint64_t*)rsp[-1];
            long int val = (long int)code_address[0];

            uint64_t* rsp_address_patched = python_callback_bb_stub(val, rsp);

            // Patch the return address to jump on the newly compiled block
            rsp[-1] = (long long int)rsp_address_patched;
        }

        // Handle the compilation of a function's stub
        void function_stub(uint64_t* rsp)
        {
            uint64_t* code_address = (uint64_t*)rsp[-1];

            // Get the two values after the stub
            int nbargs = (int)code_address[0];
            uint64_t* return_address = (uint64_t*)code_address[1];
            
            // Read values on the stack
            // For now consider we have just the name and code id
            long int name_id = rsp[1];
            long int code_id = rsp[2];
            
            //TODO: handle free variables list
            if(nbargs > 2)
                ;
    
            // Callback to python to trigger the compilation of the function
            uint64_t function_address = (uint64_t)python_callback_function_stub(name_id, code_id);

            rsp = rsp + 1;
            
            // Put on the stack the address of the next function   
            rsp[1] = (long long int)function_address;
            
            // Patch the return address
            rsp[-2] = (uint64_t)return_address;
        }

        // Handle compilation of a type-test stub
        void type_test_stub(uint64_t* rsp)
        {
            uint64_t* code_address = (uint64_t*)rsp[-1]; 
            
            int id_variable = (int)code_address[0];
            int type_value = (int)code_address[1];
            
            printf("Return value from callback %ld\\n", python_callback_type_stub(rsp[-1], id_variable, type_value));
            
            //asm("INT3");
        }
        
        void print_stack(uint64_t* rsp)
        {
            printf("Print the stack\\n");
            for(int i=-5; i!=5; i++)
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
        int twopy_library_print_integer(int value)
        {
            // Remove the integer tag for the print
            printf("%d\\n", value >> 2);
            
            return value;
        }
    """
# C Sources
ffi.set_source("stub_module", c_code)

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

        # Dictionary between stub ids and blocks to compile
        self.stub_dictionary = {}

    # Compile a stub because of a branch instruction
    # mfunction : The current compiled function
    # true_block : if the condition is true jump to this basic block
    # false_block : if the condition is false jump to this basic block
    def compile_bb_stub(self, mfunction, true_block, false_block):

        # Save both offsets
        old_stub_offset = mfunction.allocator.stub_offset
        old_code_offset = mfunction.allocator.code_offset

        # Compile a stub for each branch
        self.compile_stub(mfunction, id(true_block))

        address_false = self.compile_stub(mfunction, id(false_block))

        # And update the dictionary of ids and blocks
        # Compute the offset to the stub, by adding the size of the JL instruction
        offset = old_stub_offset - old_code_offset
        peachpy_instruction = asm.JL(asm.operand.RIPRelativeOffset(offset - 6))

        mfunction.allocator.encode(peachpy_instruction)

        jump_stub = StubBB(true_block, peachpy_instruction, old_code_offset)
        self.stub_dictionary[id(true_block)] = jump_stub

        # For now, jump to the newly compiled stub,
        # This code will be patched later
        old_code_offset = mfunction.allocator.code_offset
        peachpy_instruction = asm.MOV(asm.r10, address_false)
        mfunction.allocator.encode(peachpy_instruction)
        mfunction.allocator.encode(asm.JMP(asm.r10))

        # We store the MOV into the register as the jumping instruction, we just need to patch this
        notjump_stub = StubBB(false_block, peachpy_instruction, old_code_offset)
        self.stub_dictionary[id(false_block)] = notjump_stub

    # Compile a call to a stub with an identifier
    # mfunction: The simple_interpreter.Function
    # stub_id : The id the identifier of the block
    def compile_stub(self, mfunction, stub_id):

        # The call to that will be compiled after the stub compilation is over
        stub_label = "Stub_label_" + str(stub_id)

        # Now we store the stack pointer to patch it later
        address = mfunction.allocator.encode_stub(asm.MOV(asm.rdi, asm.registers.rsp))

        # Save the association
        mfunction.allocator.jump_labels[address] = stub_label

        reg_id = asm.r10

        function_address = int(ffi.cast("intptr_t", ffi.addressof(lib, "bb_stub")))
        mfunction.allocator.encode_stub(asm.MOV(reg_id, function_address))

        mfunction.allocator.encode_stub(asm.CALL(reg_id))

        # Put some values after the stub to read them from C with the rsp
        stub_id_bytes = stub_id.to_bytes(stub_id.bit_length(), "little")

        offset = mfunction.allocator.stub_offset
        mfunction.allocator.stub_offset = mfunction.allocator.write_instruction(stub_id_bytes, offset)

        return address

    # Compile a stub to a function
    # mfunction: The simple_interpreter.Function
    # nbargs : number of arguments in the registers, used by C function later
    # address_after : where to jump after the stub
    def compile_function_stub(self, mfunction, nbargs, address_after):
        # Now encode the stub
        stub_label = asm.Label("Stub_label_" + str(mfunction.name))

        # The call to that will be compiled after the stub compilation is over
        address = mfunction.allocator.encode_stub(asm.LABEL(stub_label))

        # Save the association
        mfunction.allocator.jump_labels[address] = asm.LABEL(stub_label)

        # Save the rsp for the stub
        mfunction.allocator.encode_stub(asm.MOV(asm.rdi, asm.registers.rsp))

        # Call the stub function in C
        function_address = int(ffi.cast("intptr_t", ffi.addressof(lib, "function_stub")))
        mfunction.allocator.encode_stub(asm.MOV(asm.r10, function_address))
        mfunction.allocator.encode_stub(asm.CALL(asm.r10))

        # Now put additional informations for the stub
        # Force min 8 bits encoding for this value
        nbargs_bytes = encode_bytes(nbargs)

        address_after_bytes = address_after.to_bytes(address_after.bit_length(), "little")

        # Write after the stub
        mfunction.allocator.stub_offset = mfunction.allocator.write_instruction(nbargs_bytes, mfunction.allocator.stub_offset)
        mfunction.allocator.stub_offset = mfunction.allocator.write_instruction(address_after_bytes, mfunction.allocator.stub_offset)

        return address

# This function is called when a stub is executed, we must compile the appropriate block and replace some code
# stub_id : The identifier of the basic block to compile
@ffi.def_extern()
def python_callback_bb_stub(stub_id, rsp):

    # We must now trigger the compilation of the corresponding block
    stub = stubhandler_instance.stub_dictionary[stub_id]

    # Delete the entry
    del stubhandler_instance.stub_dictionary[stub_id]

    # Get the offset of the first instruction compiled in the block
    first_offset = jitcompiler_instance.compile_instructions(stub.block.function, stub.block)

    # Patch the old code to not jump again in the stub
    stub.patch_instruction(first_offset)

    if jitcompiler_instance.interpreter.args.asm:
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

    if jitcompiler_instance.interpreter.args.asm:
        function.allocator.disassemble_asm()

    return function.allocator.code_address

@ffi.def_extern()
def python_callback_type_stub(return_address, id_variable, type_value):
    stub = stubhandler_instance.stub_dictionary[return_address]
    stub.callback_function(return_address, id_variable, type_value)

    # TODO: need to return an address to patch the stack
    return 42

# Encode a value to a byte by forcing 8 bits minimum
def encode_bytes(value):
    return value.to_bytes(8 if value.bit_length() < 8 else value.bit_length(), "little")

# Used to patch the code after the compilation of a stub
class Stub:
    def __init__(self):
        pass

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

                size = custom_ceil(new_operand / 256)
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

# A stub for a basic block compilation
class StubBB(Stub):
    # block : The BasicBlock compiled by this stub
    # instruction : The peachpy assembly instruction which jump to the stub
    # position : position of this instruction in the code segment (offset of the beginning)
    def __init__(self, block, instruction, position):
        self.block = block
        self.instruction = instruction
        self.position = position

    def __str__(self):
        return "(Block = " + str(id(self.block)) + " instruction " + str(self.instruction) + " position " + str(self.position) + ")"


# Stub to a function compilation
class StubFunction(Stub):
    def __init__(self):
        pass


# A class to generate stub for type tests
class StubType(Stub):
    # instructions : the instruction to encode
    # mfunction : currently compiled function
    # true_branch : instructions for the true branch
    # false_branch : instructions for the false branch
    # variable : 0 or 1 to indicate which operands is tested here
    # context : associated context we try to fill
    def __init__(self, mfunction, instructions, true_branch, false_branch, variable, context):
        self.mfunction = mfunction
        self.instructions = instructions
        self.true_branch = true_branch
        self.false_branch = false_branch
        self.variable = variable

        # Associate return addresses to branch of the test to know which one was executed
        self.dict_stubs = {}

        self.context = context
        self.encode_instructions()

    def encode_instructions(self):
        # Encoding the test
        for i in self.instructions:
            self.mfunction.allocator.encode(i)

        # Encode the true branch first
        old_stub_offset = self.mfunction.allocator.stub_offset

        self.encode_stub_test(self.true_branch, "true_branch", objects.Types.Int)

        true_offset =  old_stub_offset - self.mfunction.allocator.code_offset - 6
        self.mfunction.allocator.encode(asm.JE(asm.operand.RIPRelativeOffset(true_offset)))

        # Jump to false branch
        #false_address = self.encode_stub_test(self.false_branch, "false_branch")
        #self.mfunction.encode(asm.MOV(asm.r10, false_address))
        #self.mfunction.allocator.encode(asm.JMP(asm.r10))

    # Encode a stub to continue the test
    def encode_stub_test(self, branch, label, type_value):
        # Giving rsp to C function
        address = self.mfunction.allocator.encode_stub(asm.MOV(asm.rdi, asm.registers.rsp))

        # Save the association
        self.mfunction.allocator.jump_labels[address] = label

        # Call to C to compile the block
        reg_id = asm.r10
        function_address = int(ffi.cast("intptr_t", ffi.addressof(lib, "type_test_stub")))
        self.mfunction.allocator.encode_stub(asm.MOV(reg_id, function_address))
        self.mfunction.allocator.encode_stub(asm.CALL(reg_id))

        # Compute the return address to link this stub to self
        return_address = lib.get_address(ffi.from_buffer(self.mfunction.allocator.code_section), self.mfunction.allocator.stub_offset)
        self.dict_stubs[return_address] = branch

        # Associate this return address to self in the stub_handler
        stubhandler_instance.stub_dictionary[return_address] = self

        variable_id = encode_bytes(self.variable)
        type_bytes = encode_bytes(type_value.value)

        offset = self.mfunction.allocator.stub_offset
        self.mfunction.allocator.stub_offset = self.mfunction.allocator.write_instruction(variable_id, offset)
        self.mfunction.allocator.stub_offset = self.mfunction.allocator.write_instruction(type_bytes, self.mfunction.allocator.stub_offset)

    # TODO: Called by C when one branch of this test is triggered
    def callback_function(self, return_address, id_variable, type_value):

        self.context.variable_types[id_variable] = type_value
        # We have information on one operand

        jitcompiler_instance.tags.compile_test(self.context)

        # TODO: Compile the rest of the test
        if self.dict_stubs[return_address] == self.true_branch:
           pass
        else:
            pass


# Ceil without using the math library
def custom_ceil(n):
    res = int(n)
    return res if res == n or n < 0 else res+1

twopy_primitives = [
"twopy_abs",
"twopy_dict",
"twopy_help",
"twopy_min",
"twopy_setattr",
"twopy_all",
"twopy_dir",
"twopy_hex",
"twopy_next",
"twopy_slice",
"twopy_any",
"twopy_divmod",
"twopy_id",
"twopy_object",
"twopy_sorted",
"twopy_ascii",
"twopy_enumerate",
"twopy_input",
"twopy_oct",
"twopy_staticmethod",
"twopy_bin",
"twopy_eval",
"twopy_int",
"twopy_open",
"twopy_str",
"twopy_bool",
"twopy_exec",
"twopy_isinstance",
"twopy_ord",
"twopy_sum",
"twopy_bytearray",
"twopy_filter",
"twopy_issubclass",
"twopy_pow",
"twopy_super",
"twopy_bytes",
"twopy_float",
"twopy_iter",
"twopy_print",
"twopy_tuple",
"twopy_callable",
"twopy_format",
"twopy_len",
"twopy_property",
"twopy_type",
"twopy_chr",
"twopy_frozenset",
"twopy_list",
"twopy_range",
"twopy_vars",
"twopy_classmethod",
"twopy_getattr",
"twopy_locals",
"twopy_repr",
"twopy_zip",
"twopy_globals",
"twopy_map",
"twopy_reversed",
"twopy___import__",
"twopy_complex",
"twopy_hasattr",
"twopy_max",
"twopy_round",
"twopy_hash",
"twopy_delattr",
"twopy_memoryview",
"twopy_set"]

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
"print" : 0,
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