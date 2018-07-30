# coding=utf-8
# Make the link between compiled assembly and high-level python functions
# Handle the compilation of stub functions
import peachpy.x86_64 as asm
from jit import objects
from jit import ffi_definitions

# Import of the generated C-FFI module
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

        # Association between stub identifiers and their data addresses
        self.data_addresses = {}

        # The unique stub for printing errors during execution, will call a C function
        self.stub_error = None

        # Addresses of the beginning of class stubs to identify them during a callback
        self.class_stub_addresses = list()

    # Compile a stub which jumps without condition to a block
    # mfunction : current compiled function
    # block : the target of the jump
    def compile_absolute_jump(self, mfunction, block):

        stub_label = "Stub_label_jump" + str(id(block))

        old_code_offset = jitcompiler_instance.global_allocator.code_offset

        c_buffer = ffi.from_buffer(jitcompiler_instance.global_allocator.code_section)
        address = lib.get_address(c_buffer, jitcompiler_instance.global_allocator.stub_offset)

        jump_instruction = asm.MOV(asm.r10, address)
        mfunction.allocator.encode(jump_instruction)
        mfunction.allocator.encode(asm.JMP(asm.r10))

        # Now create the stub
        stub = StubBB(block, jump_instruction, old_code_offset)
        self.compile_stub(mfunction, stub)

    # Compile a stub because of a branch instruction
    # mfunction : The current compiled function
    # true_block : if the condition is true jump to this basic block
    # false_block : if the condition is false jump to this basic block
    # test_intruction : the class of instruction to for the test
    def compile_bb_stub(self, mfunction, true_block, false_block, test_instruction):

        # Save both offsets
        old_stub_offset = jitcompiler_instance.global_allocator.stub_offset
        old_code_offset = jitcompiler_instance.global_allocator.code_offset

        # And update the dictionary of ids and blocks
        # Compute the offset to the stub, by adding the size of the JL instruction
        offset = old_stub_offset - old_code_offset
        peachpy_instruction = test_instruction(asm.operand.RIPRelativeOffset(offset - 6))

        mfunction.allocator.encode(peachpy_instruction)

        # Compile a stub for each branch
        jump_stub = StubBB(true_block, peachpy_instruction, old_code_offset)
        self.compile_stub(mfunction, jump_stub)

        # For now, jump to the newly compiled stub,
        # This code will be patched later
        old_code_offset = jitcompiler_instance.global_allocator.code_offset

        # Compute the address of the false block stub
        c_buffer = ffi.from_buffer(jitcompiler_instance.global_allocator.code_section)
        address_false = lib.get_address(c_buffer, jitcompiler_instance.global_allocator.stub_offset)

        peachpy_instruction = asm.MOV(asm.r10, address_false)
        mfunction.allocator.encode(peachpy_instruction)
        mfunction.allocator.encode(asm.JMP(asm.r10))

        # We store the MOV into the register as the jumping instruction, we just need to patch this
        notjump_stub = StubBB(false_block, peachpy_instruction, old_code_offset)
        self.compile_stub(mfunction, notjump_stub)

    # Compile a call to a stub with an identifier
    # mfunction: The simple_interpreter.Function
    # stub : The associated StubBB object
    def compile_stub(self, mfunction, stub):

        # The call to that will be compiled after the stub compilation is over
        stub_label = "Stub_label_" + str(id(stub))

        # Now we store the stack pointer to patch it later
        address = mfunction.allocator.encode_stub(asm.MOV(asm.rdi, asm.registers.rsp))

        # Save the association
        mfunction.allocator.jump_labels[address] = stub_label

        reg_id = asm.r10

        function_address = int(ffi.cast("intptr_t", ffi.addressof(lib, "bb_stub")))

        # Align the stack on 16 bits

        mfunction.allocator.encode_stub(asm.MOV(asm.rax, asm.registers.rsp))
        mfunction.allocator.encode_stub(asm.PUSH(asm.registers.rsp))

        mfunction.allocator.encode_stub(asm.MOV(reg_id, function_address))

        mfunction.allocator.encode_stub(asm.CALL(reg_id))

        # Save the offset
        offset = jitcompiler_instance.global_allocator.stub_offset

        return_address = lib.get_address(ffi.from_buffer(jitcompiler_instance.global_allocator.code_section),
                        jitcompiler_instance.global_allocator.stub_offset)

        # Indicate this offset correspond to the "return address" on the stub after the call to C returned
        self.data_addresses[return_address] = offset
        self.stub_dictionary[return_address] = stub

        # Save some space for cleaning instructions
        for i in range(15):
            mfunction.allocator.encode_stub(asm.NOP())

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

        for i in range(5):
            mfunction.allocator.encode_stub(asm.NOP())

        return address

    # Compile a jump to an error
    # error_code The code of the error sent to C
    def compile_error_stub(self, error_code):
        if not self.stub_error:
            self.stub_error = StubError()

        address = jitcompiler_instance.global_allocator.encode_stub(asm.MOV(asm.rdi, error_code))

        function_address = int(ffi.cast("intptr_t", ffi.addressof(lib, "twopy_error")))

        jitcompiler_instance.global_allocator.encode_stub(asm.MOV(asm.r10, function_address))
        jitcompiler_instance.global_allocator.encode_stub(asm.CALL(asm.r10))

        return address

    # A stub to generate a class and its model
    def compile_class_stub(self, mfunction):
        # Push on the stack the address of the class' stub
        c_buffer = ffi.from_buffer(jitcompiler_instance.global_allocator.code_section)
        address_stub = lib.get_address(c_buffer, jitcompiler_instance.global_allocator.stub_offset)

        mfunction.allocator.encode(asm.MOV(asm.r10, address_stub))
        mfunction.allocator.encode(asm.PUSH(asm.r10))

        # Save the address after the PUSH to be able to jump there later
        c_buffer = ffi.from_buffer(jitcompiler_instance.global_allocator.code_section)
        address_code = lib.get_address(c_buffer, jitcompiler_instance.global_allocator.code_offset)

        # Be able to find them in the collection during the later callback
        self.class_stub_addresses.append(address_stub)

        # Call the stub function
        mfunction.allocator.encode_stub(asm.MOV(asm.rdi, asm.registers.rsp))

        function_address = int(ffi.cast("intptr_t", ffi.addressof(lib, "class_stub")))
        mfunction.allocator.encode_stub(asm.MOV(asm.r10, function_address))
        mfunction.allocator.encode_stub(asm.CALL(asm.r10))

        offset = jitcompiler_instance.global_allocator.stub_offset

        return_address = lib.get_address(ffi.from_buffer(jitcompiler_instance.global_allocator.code_section),
                                         jitcompiler_instance.global_allocator.stub_offset)

        stub = StubClass()
        stub.data_address = offset
        stub.return_address = address_code

        # Indicate this offset correspond to the "return address" on the stub after the call to C returned
        self.data_addresses[return_address] = offset
        self.stub_dictionary[return_address] = stub

        # Reserve some space for the cleanup
        for i in range(5):
            mfunction.allocator.encode_stub(asm.NOP())


# This function is called when a stub is executed, we must compile the appropriate block and replace some code
# rsp : The return address, use to identify which stub we must compile
@ffi.def_extern()
def python_callback_bb_stub(rsp):

    # We must now trigger the compilation of the corresponding block
    stub = stubhandler_instance.stub_dictionary[rsp]

    # Get the offset of the first instruction compiled in the block
    first_offset = jitcompiler_instance.compile_instructions(stub.block.function, stub.block)

    # Patch the old code to not jump again in the stub
    stub.patch_instruction(first_offset)

    if jitcompiler_instance.interpreter.args.asm:
        jitcompiler_instance.global_allocator.disassemble_asm()

    c_buffer = ffi.from_buffer(jitcompiler_instance.global_allocator.code_section)
    rsp_address_patched = lib.get_address(c_buffer, first_offset)
    stub.data_address = stubhandler_instance.data_addresses[rsp]

    stub.clean(rsp_address_patched)

    # Delete the entry
    del stubhandler_instance.stub_dictionary[rsp]


# This function is called when a stub is executed, need to compile a function
@ffi.def_extern()
def python_callback_function_stub(name_id, code_id, return_address, canary_value):
    # Generate the Function object in the model
    name = jitcompiler_instance.consts[name_id]
    code = jitcompiler_instance.consts[code_id]

    function = jitcompiler_instance.interpreter.generate_function(code, name, jitcompiler_instance.interpreter.mainmodule, False)

    # We may need to generate a class
    if canary_value in stubhandler_instance.class_stub_addresses:
        function.is_class = True
        function.mclass = objects.JITClass(function, name)

        # Add this class-function to the global collection
        jitcompiler_instance.class_functions.append(function)

    # Trigger the compilation of the given function
    jitcompiler_instance.compile_function(function)

    if jitcompiler_instance.interpreter.args.asm:
        jitcompiler_instance.global_allocator.disassemble_asm()

    stub = stubhandler_instance.stub_dictionary[return_address]
    stub.data_address = stubhandler_instance.data_addresses[return_address]

    stub.clean(return_address, function.allocator.code_address, canary_value)


@ffi.def_extern()
def python_callback_type_stub(return_address, id_variable, type_value):
    stub = stubhandler_instance.stub_dictionary[return_address]

    stub.callback_function(return_address, id_variable, type_value)


@ffi.def_extern()
def python_callback_class_stub(return_address, address_after):
    stub = stubhandler_instance.stub_dictionary[return_address]

    # Find the last created class to call if after this stub
    last_function = jitcompiler_instance.class_functions[-1]

    # Allocate the class and return its tagged values
    class_address = jitcompiler_instance.global_allocator.allocate_class(last_function)

    address_class_function = jitcompiler_instance.dict_compiled_functions[last_function]

    stub.return_address = address_after

    # Clean the stub and put the class address on the stack
    stub.clean(class_address, address_class_function)


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
            if diff > 0 and diff <= 13:
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
        elif isinstance(self.instruction, asm.JNE):
            new_operand = first_offset - self.position - len(self.instruction.encode())
            if new_operand < 255:
                # We will encode the instruction
                new_operand = first_offset - self.position - 2

            new_instruction = asm.JNE(asm.operand.RIPRelativeOffset(new_operand))
            encoded = new_instruction.encode()

            # Need to add some NOP instruction to fill the space left from the previous longer instruction
            if len(encoded) < len(self.instruction.encode()):

                diff = len(self.instruction.encode()) - len(encoded)

                for i in range(diff):
                    encoded += asm.NOP().encode()
            else:
                # If the previous instruction was a 32 bits offset, force the same length for the new one
                encoded = bytearray(len(self.instruction.encode()))

                # Force the 32 encoding of the JNE instruction
                encoded[0] = 0x0F
                encoded[1] = 0x85
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
    # canary_value : if specified, indicate a special value on the stack which needs to be cleaned
    def clean(self, return_address, function_address, canary_value=None):
        instructions = []

        # restore rsp
        instructions.append(asm.POP(asm.registers.rsp).encode())

        if canary_value in stubhandler_instance.class_stub_addresses:
            instructions.append(asm.ADD(asm.registers.rsp, 32).encode())
        else:
            # Discard the three top values on the stack
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
        self.mfunction.allocator.encode_stub(asm.PUSH(asm.registers.rsp))

        self.mfunction.allocator.encode_stub(asm.MOV(reg_id, function_address))
        self.mfunction.allocator.encode_stub(asm.CALL(reg_id))

        # Compute the return address to link this stub to self
        return_address = lib.get_address(ffi.from_buffer(jitcompiler_instance.global_allocator.code_section), jitcompiler_instance.global_allocator.stub_offset)

        return_address = return_address & -16
        # Associate this return address to self in the stub_handler
        stubhandler_instance.stub_dictionary[return_address] = self

        variable_id = encode_bytes(self.variable)
        type_bytes = encode_bytes(type_value)

        offset = jitcompiler_instance.global_allocator.stub_offset

        stubhandler_instance.data_addresses[return_address] = offset

        jitcompiler_instance.global_allocator.stub_offset = jitcompiler_instance.global_allocator.write_instruction(variable_id, offset)
        jitcompiler_instance.global_allocator.stub_offset = jitcompiler_instance.global_allocator.write_instruction(type_bytes, jitcompiler_instance.global_allocator.stub_offset)

        # Saving some space for the cleaning
        for i in range(5):
            self.mfunction.allocator.encode_stub(asm.NOP())

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


# A stub to handle the creation of a class
class StubClass(Stub):
    def __init__(self):
        super().__init__()

    # Write instructions to restore the context before returning to asm
    # return_address : where to jump after this stub
    # class_address : address of the created class, to put on TOS after returning
    # address_class_function : address of the class-function to call
    def clean(self, class_address, address_class_function):
        instructions = []

        # Now push the function address
        instructions.append(asm.MOV(asm.rax, class_address))
        instructions.append(asm.PUSH(asm.rax))

        instructions.append(asm.MOV(asm.r10, address_class_function))
        instructions.append(asm.CALL(asm.r10))

        # Clean the stack
        instructions.append(asm.ADD(asm.registers.rsp, 32))

        # Finally, jump to the correct destination
        instructions.append(asm.MOV(asm.rax, class_address))
        instructions.append(asm.MOV(asm.rbx, self.return_address))
        instructions.append(asm.JMP(asm.rbx))

        offset = self.data_address
        for i in instructions:
            offset = jitcompiler_instance.global_allocator.write_instruction(i.encode(), offset)


# Jump to this stub to print an error an stop the execution
class StubError(Stub):
    def __init__(self):
        super().__init__()


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