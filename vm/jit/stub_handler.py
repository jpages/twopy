# coding=utf-8
# Make the link between compiled assembly and high-level python functions
# Handle the compilation of stub functions
import cffi
import math
import peachpy.x86_64 as asm
from . import objects
from . import compiler

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
        extern "Python+C" char* python_callback_bb_stub(uint64_t stub_id, uint64_t* rsp);
        
        // Callback to trigger the compilation of a function
        extern "Python+C" char* python_callback_function_stub(uint64_t, uint64_t, uint64_t);

        // Callback for type tests
        extern "Python+C" uint64_t python_callback_type_stub(uint64_t, int, int);

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
    """)

c_code = """
        #include <stdio.h>
        #include <stdlib.h>

        // Function called to handle the compilation of stubs for basic blocks
        static char* python_callback_bb_stub(uint64_t stub_id, uint64_t* rsp);
        
        static char* python_callback_function_stub(uint64_t, uint64_t, uint64_t);
        
        static uint64_t python_callback_type_stub(uint64_t, int, int);

        void bb_stub(uint64_t* rsp)
        {
            // Read values after the stub
            uint64_t* code_address = (uint64_t*)rsp[-2];
             
            long int val = (long int)code_address[0];
            
            python_callback_bb_stub(val, rsp);
        }

        // Handle the compilation of a function's stub
        void function_stub(uint64_t* rsp)
        {  
            uint64_t* code_address = (uint64_t*)rsp[-1];

            // Get the two values after the stub
            int nbargs = (int)code_address[0];
            uint64_t* return_address = rsp[0];

            // Read values on the stack
            // For now consider we have just the name and code id
            long int name_id = rsp[1];
            long int code_id = rsp[2];
            
            //TODO: handle free variables list
            if(nbargs > 2)
                ;
            
            //print_stack(rsp);
            
            // Callback to python to trigger the compilation of the function
            python_callback_function_stub(name_id, code_id, (uint64_t)return_address);

            //rsp = rsp + 1;
            
            // Put on the stack the address of the next function
            //rsp[1] = (long long int)function_address;
            
            // Patch the return address
            //rsp[-2] = (uint64_t)return_address;
        }

        // Handle compilation of a type-test stub
        void type_test_stub(uint64_t* rsp)
        {
            uint64_t* code_address = (uint64_t*)rsp[-3]; 
            
            int id_variable = (int)code_address[0];
            int type_value = (int)code_address[1];
            
            // Get the return address
            long int return_address = rsp[-3];
            
            return_address = return_address & -16;

            python_callback_type_stub(return_address, id_variable, type_value);
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

        long int twopy_print(long int value)
        {
            // Test the tag of the object
            int tag = (int)value & 3;

            if(tag == 1)
                return twopy_library_print_boolean(value);
            else if(tag == 0)
                return twopy_library_print_integer(value);
            
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

        # TODO: temporary, association between stub ids and their data addresses
        self.data_addresses = {}

    # Compile a stub because of a branch instruction
    # mfunction : The current compiled function
    # true_block : if the condition is true jump to this basic block
    # false_block : if the condition is false jump to this basic block
    def compile_bb_stub(self, mfunction, true_block, false_block):

        # Save both offsets
        old_stub_offset = jitcompiler_instance.global_allocator.stub_offset
        old_code_offset = jitcompiler_instance.global_allocator.code_offset

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

        jump_stub.data_address = self.data_addresses[id(true_block)]

        # For now, jump to the newly compiled stub,
        # This code will be patched later
        old_code_offset = jitcompiler_instance.global_allocator.code_offset
        peachpy_instruction = asm.MOV(asm.r10, address_false)
        mfunction.allocator.encode(peachpy_instruction)
        mfunction.allocator.encode(asm.JMP(asm.r10))

        # We store the MOV into the register as the jumping instruction, we just need to patch this
        notjump_stub = StubBB(false_block, peachpy_instruction, old_code_offset)
        self.stub_dictionary[id(false_block)] = notjump_stub
        notjump_stub.data_address = self.data_addresses[id(false_block)]

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

        print("Stub_id " + str(stub_id))
        # Align the stack on 16 bits

        mfunction.allocator.encode_stub(asm.MOV(asm.rax, asm.registers.rsp))
        mfunction.allocator.encode_stub(asm.AND(asm.registers.rsp, -16))
        mfunction.allocator.encode_stub(asm.PUSH(asm.registers.rsp))

        mfunction.allocator.encode_stub(asm.MOV(reg_id, function_address))

        mfunction.allocator.encode_stub(asm.CALL(reg_id))

        # Put some values after the stub to read them from C with the rsp
        stub_id_bytes = stub_id.to_bytes(stub_id.bit_length(), "little")

        offset = jitcompiler_instance.global_allocator.stub_offset

        # Save some space for cleaning instructions
        mfunction.allocator.encode_stub(asm.NOP())

        # Indicate this offset correspond to the "return address" on the stub after the call to C returned
        self.data_addresses[stub_id] = offset
        jitcompiler_instance.global_allocator.stub_offset = jitcompiler_instance.global_allocator.write_instruction(stub_id_bytes, offset)

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

        # Align the stack on 16 bits
        mfunction.allocator.encode_stub(asm.MOV(asm.rax, asm.registers.rsp))
        mfunction.allocator.encode_stub(asm.AND(asm.registers.rsp, -16))
        # mfunction.allocator.encode_stub(asm.SUB(asm.registers.rsp, 8))
        mfunction.allocator.encode_stub(asm.PUSH(asm.registers.rsp))

        mfunction.allocator.encode_stub(asm.MOV(asm.r10, function_address))
        mfunction.allocator.encode_stub(asm.CALL(asm.r10))

        # Now put additional informations for the stub
        # Force min 8 bits encoding for this value
        nbargs_bytes = encode_bytes(nbargs)

        stub_function = StubFunction()
        self.stub_dictionary[address_after] = stub_function

        self.data_addresses[address_after] = jitcompiler_instance.global_allocator.stub_offset

        address_after_bytes = address_after.to_bytes(address_after.bit_length(), "little")

        # Write after the stub
        jitcompiler_instance.global_allocator.stub_offset = jitcompiler_instance.global_allocator.write_instruction(nbargs_bytes, jitcompiler_instance.global_allocator.stub_offset)
        jitcompiler_instance.global_allocator.stub_offset = jitcompiler_instance.global_allocator.write_instruction(address_after_bytes, jitcompiler_instance.global_allocator.stub_offset)

        return address

# This function is called when a stub is executed, we must compile the appropriate block and replace some code
# stub_id : The identifier of the basic block to compile
@ffi.def_extern()
def python_callback_bb_stub(stub_id, rsp):

    print("test")
    # TODO: use the rsp to identify the stub instead of its id
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

    c_buffer = ffi.from_buffer(jitcompiler_instance.global_allocator.code_section)
    rsp_address_patched = lib.get_address(c_buffer, first_offset)

    stub.clean(rsp_address_patched)

    return ffi.cast("char*", rsp_address_patched)

# This function is called when a stub is executed, need to compile a function
@ffi.def_extern()
def python_callback_function_stub(name_id, code_id, return_address):
    # Generate the Function object in the model
    name = jitcompiler_instance.consts[name_id]
    code = jitcompiler_instance.consts[code_id]

    function = jitcompiler_instance.interpreter.generate_function(code, name, jitcompiler_instance.interpreter.mainmodule, False)

    # Trigger the compilation of the given function
    jitcompiler_instance.compile_function(function)

    if jitcompiler_instance.interpreter.args.asm:
        function.allocator.disassemble_asm()

    print(stubhandler_instance.stub_dictionary[return_address])
    stub = stubhandler_instance.stub_dictionary[return_address]
    stub.data_address = stubhandler_instance.data_addresses[return_address]

    #TODO: to finish
    stub.clean(return_address, function.allocator.code_address)

    return ffi.cast("char*", function.allocator.code_address)

@ffi.def_extern()
def python_callback_type_stub(return_address, id_variable, type_value):
    stub = stubhandler_instance.stub_dictionary[return_address]
    address = stub.callback_function(return_address, id_variable, type_value)

    return address

# Encode a value to a byte by forcing 8 bits minimum
def encode_bytes(value):
    return value.to_bytes(8 if value.bit_length() < 8 else value.bit_length(), "little")

# Used to patch the code after the compilation of a stub
class Stub:
    def __init__(self):

        # Offset in the code section where data are written for this stub
        self.data_address = None

    # Patch the instruction after the stub compilation
    # first_offset : offset of the first instruction newly compiled in the block
    def patch_instruction(self, first_offset):

        if isinstance(self.instruction, asm.MOV):
            # Moving an address inside a register, we need to change the address here

            # If the MOVE + JUMP is supposed to go just after, put NOP instead
            diff = first_offset - self.position
            if diff <= 13:
                nop = asm.NOP().encode()
                for i in range(diff):
                    jitcompiler_instance.global_allocator.write_instruction(nop, self.position)
                    self.position += 1
            else:
                # It's a real jump, just compile it and patch the code
                new_address = lib.get_address(ffi.from_buffer(jitcompiler_instance.global_allocator.code_section), first_offset)
                new_instruction = asm.MOV(self.instruction.operands[0], new_address)

                # Create the new encoded instruction and replace the old one in the code section
                encoded = new_instruction.encode()
                jitcompiler_instance.global_allocator.write_instruction(encoded, self.position)
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

            jitcompiler_instance.global_allocator.write_instruction(encoded, self.position)
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

            jitcompiler_instance.global_allocator.write_instruction(encoded, self.position)
        elif isinstance(self.instruction, asm.JE):

            new_operand = first_offset - self.position - len(self.instruction.encode())

            # Update to the new position
            new_instruction = asm.JE(asm.operand.RIPRelativeOffset(new_operand))
            encoded = new_instruction.encode()

            # If the previous instruction was a 32 bits offset, force it to the new one
            if len(self.instruction.encode()) > 2:
                encoded = bytearray(len(self.instruction.encode()))

                # Force the 32 encoding of the JE instruction
                encoded[0] = 0x0F
                encoded[1] = 0x84
                encoded[2] = 0
                encoded[3] = 0
                encoded[4] = 0
                encoded[5] = 0

                size = custom_ceil(new_operand / 256)
                bytes = new_operand.to_bytes(size, 'big')

                for i in range(0, len(bytes)):
                    encoded[i+2] = bytes[i]

            jitcompiler_instance.global_allocator.write_instruction(encoded, self.position)
        elif isinstance(self.instruction, asm.JL):
            new_operand = first_offset - self.position - len(self.instruction.encode())

            new_instruction = asm.JL(asm.operand.RIPRelativeOffset(new_operand))
            encoded = new_instruction.encode()

            # If the previous instruction was a 32 bits offset, force the same length for the new one
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
                bytes = new_operand.to_bytes(size, 'little')

                for i in range(0, len(bytes)):
                    encoded[i + 2] = bytes[i]

            jitcompiler_instance.global_allocator.write_instruction(encoded, self.position)
        else:
            print("Not yet implemented patch")

    # Write instructions to restore the context before returning to asm
    def clean(self, return_address):

        print("Cleaning from " + str(self))
        instructions = []
        instructions.append(asm.POP(asm.registers.rsp).encode())
        instructions.append(asm.MOV(asm.rax, return_address).encode())
        instructions.append(asm.JMP(asm.rax).encode())

        offset = self.data_address
        for i in instructions:
            offset = jitcompiler_instance.global_allocator.write_instruction(i, offset)


# A stub for a basic block compilation
class StubBB(Stub):
    # block : The BasicBlock compiled by this stub
    # instruction : The peachpy assembly instruction which jump to the stub
    # position : position of this instruction in the code segment (offset of the beginning)
    def __init__(self, block, instruction, position):

        super().__init__()

        self.block = block
        self.instruction = instruction
        self.position = position

    def __str__(self):
        return "(Block = " + str(id(self.block)) + " instruction " + str(self.instruction) + " position " + str(self.position) + ")"

# Stub to a function compilation
class StubFunction(Stub):
    def __init__(self):
        super().__init__()

    # Write instructions to restore the context before returning to asm
    # return_address : where to jump after this stub
    # function_address : address of the newly compiled function, to put on TOS after returning
    def clean(self, return_address, function_address):
        instructions = []

        # restore rsp
        instructions.append(asm.POP(asm.registers.rsp).encode())

        # Discard the two top values on the stack
        instructions.append(asm.ADD(asm.registers.rsp, 24).encode())

        # Now push the function address
        instructions.append(asm.MOV(asm.rax, function_address).encode())
        instructions.append(asm.PUSH(asm.rax).encode())

        # Finally, jump to the correct destination
        instructions.append(asm.MOV(asm.rax, return_address).encode())
        instructions.append(asm.JMP(asm.rax).encode())

        offset = self.data_address
        for i in instructions:
            offset = jitcompiler_instance.global_allocator.write_instruction(i, offset)

# A class to generate stub for type tests
class StubType(Stub):
    # instructions : the instruction to encode
    # mfunction : currently compiled function
    # true_branch : instructions for the true branch
    # false_branch : instructions for the false branch
    # variable : 0 or 1 to indicate which operands is tested here
    # context : associated context we try to fill
    def __init__(self, mfunction, instructions, true_branch, false_branch, variable, context):
        super().__init__()

        self.mfunction = mfunction
        self.true_branch = true_branch
        self.false_branch = false_branch
        self.variable = variable

        # Associate return addresses to instructions of the test
        self.dict_stubs = {}
        self.dict_stubs_position = {}

        self.context = context
        self.encode_instructions(instructions)

        self.first_variable = context.stack[len(context.stack)-1]
        self.second_variable = context.stack[len(context.stack)-2]

    def encode_instructions(self, instructions):
        # Encoding the test
        for i in instructions:
            self.mfunction.allocator.encode(i)

        # Encode the true branch first
        old_stub_offset = jitcompiler_instance.global_allocator.stub_offset

        return_address = self.encode_stub_test(self.true_branch, "true_branch", objects.Types.Int)

        true_offset = old_stub_offset - jitcompiler_instance.global_allocator.code_offset - 6
        old_position = jitcompiler_instance.global_allocator.code_offset
        instruction = asm.JE(asm.operand.RIPRelativeOffset(true_offset))
        self.mfunction.allocator.encode(instruction)

        self.dict_stubs[return_address] = instruction
        self.dict_stubs_position[return_address] = old_position

        #TODO: Jump to false branch
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

        # Align the stack on 16 bits
        self.mfunction.allocator.encode_stub(asm.MOV(asm.rax, asm.registers.rsp))
        self.mfunction.allocator.encode_stub(asm.AND(asm.registers.rsp, -16))
        # self.mfunction.allocator.encode_stub(asm.SUB(asm.registers.rsp, 8))
        self.mfunction.allocator.encode_stub(asm.PUSH(asm.registers.rsp))

        self.mfunction.allocator.encode_stub(asm.MOV(reg_id, function_address))
        self.mfunction.allocator.encode_stub(asm.CALL(reg_id))

        #TODO: need to pop the address after
        # Compute the return address to link this stub to self
        return_address = lib.get_address(ffi.from_buffer(jitcompiler_instance.global_allocator.code_section), jitcompiler_instance.global_allocator.stub_offset)


        print("Return address before alignment " + str(return_address))
        return_address = return_address & -16
        print("Return address now in dict " + str(return_address))
        # Associate this return address to self in the stub_handler
        stubhandler_instance.stub_dictionary[return_address] = self

        variable_id = encode_bytes(self.variable)
        type_bytes = encode_bytes(type_value)

        offset = jitcompiler_instance.global_allocator.stub_offset

        stubhandler_instance.data_addresses[return_address] = offset

        jitcompiler_instance.global_allocator.stub_offset = jitcompiler_instance.global_allocator.write_instruction(variable_id, offset)
        jitcompiler_instance.global_allocator.stub_offset = jitcompiler_instance.global_allocator.write_instruction(type_bytes, jitcompiler_instance.global_allocator.stub_offset)

        return return_address

    # Set the instructions to compile after this test is over
    # opname : name of the binary operation
    # block : the current block
    # next_index of the next instruction to compile, after the type-test
    def instructions_after(self, opname, block, next_index):
        self.opname = opname
        self.block = block
        self.next_index = next_index

    # Compile the rest of the block after this type-test
    def compile_instructions_after(self):
        jitcompiler_instance.compile_instructions(self.mfunction, self.block, self.next_index)

    # Called by C when one branch of this test is triggered
    def callback_function(self, return_address, id_variable, type_value):
        # We have information on one operand
        self.context.variable_types[id_variable] = type_value

        # If we have a type value
        if type_value != objects.Types.Unknown:
            # Test the other variable now
            if id_variable == 0:
                self.context.set_value(self.first_variable, type_value)
                self.variable = 1
            else:
                self.variable = 0
                self.context.set_value(self.second_variable, type_value)

        # Else continue to test the current one

        # Get the address of the new instructions
        c_buffer = ffi.from_buffer(jitcompiler_instance.global_allocator.code_section)
        rsp_address_patched = lib.get_address(c_buffer, jitcompiler_instance.global_allocator.code_offset)

        # Patch the previous test
        self.instruction = self.dict_stubs[return_address]
        self.position = self.dict_stubs_position[return_address]

        self.patch_instruction(jitcompiler_instance.global_allocator.code_offset)

        # Patch the previous instruction to jump to this newly compiled code
        # Compile the rest of the test and encode instructions
        instructions = jitcompiler_instance.tags.compile_test(self.context, self.opname, True)
        if self.context.variable_types[0] != objects.Types.Unknown and self.context.variable_types[1] != objects.Types.Unknown:
            for i in instructions:
                self.mfunction.allocator.encode(i)
            # Then compile the following instructions in the block
            self.compile_instructions_after()
        else:
            # We have some part of the test to compile
            self.encode_instructions(instructions)

        self.data_address = stubhandler_instance.data_addresses[return_address]
        self.clean(rsp_address_patched)

        return rsp_address_patched


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