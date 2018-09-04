'''
This module contains code relative to memory allocation and garbage collection
'''

# ASM disassembly
import capstone

import peachpy.x86_64 as asm

from . import stub_handler

# Handle allocation of the general code section
class GlobalAllocator:
    def __init__(self, jitcompiler):
        self.jitcompiler = jitcompiler

        # Size of the code section
        self.code_size = 20000

        # Size of the data section
        self.data_size = 5000

        # The next free zone in the data section
        # Offset for static allocations for now
        self.data_offset = 0

        # Offset for runtime allocations
        self.runtime_offset = 1024

        # Offset for allocate classes in a special area
        self.class_offset = 2048

        # The offset in code_section where the code can be allocated
        self.code_offset = 0

        # The stub pointer is in the end of the code section
        self.stub_offset = 15000

        # Future code and data sections, type buffer from ffi
        self.code_section = None
        self.data_section = None

        # C arrays of code and data sections
        self.code_buffer = None
        self.data_buffer = None

        # Integer values of addresses of C arrays
        self.code_address = None
        self.data_address = None

        # Future code address
        self.general_code_address = None

        # Future data address
        self.general_data_address = None

        # Allocate the code segment in C
        self.allocate_code_segment()

        self.runtime_allocator = None

    # Allocate an executable segment of code
    def allocate_code_segment(self):

        # Allocate code segment
        code_address = stub_handler.lib.allocate_code_section(self.code_size)

        self.code_address = int(stub_handler.ffi.cast("uint64_t", code_address))

        if code_address == -1:
            raise OSError("Failed to allocate memory for code segment")

        self.code_buffer = code_address

        if self.data_size > 0:

            data_address = stub_handler.lib.allocate_data_section(self.data_size)
            self.data_address = int(stub_handler.ffi.cast("uint64_t", code_address))

            if data_address == -1:
                raise OSError("Failed to allocate memory for data segment")
            self.data_buffer = data_address

        # Create manipulable python arrays for these two sections
        self.python_arrays()

    # Allocate a new blank class object to be filled later
    # mfunction: the function of the class
    # Each word of a class is 64 bits
    # | header | new_instance | method1 | method2 | ...
    # The second field is a pointer to the new_instance code for this class
    # TODO: get an indication on the size (number of methods) of the class
    def allocate_class(self, mfunction):
        # TODO: Try to know the size of the structure we need to allocate

        init_function = self.jitcompiler.locate_init(mfunction)

        # Save the address of this object
        address = self.get_current_class_address()

        # TODO: for the test consider only 4 values inside the class
        size = 5 * 64

        # SIZE    64 bits |      Array of pointers
        encoded_size = size.to_bytes(8, "little")

        # Write the size
        self.class_offset = self.write_data(encoded_size, self.class_offset)

        # Put the tag to indicate a memory object
        tagged_address = self.jitcompiler.tags.tag_object(address)

        # Now we need to store the pointer to the new instance code inside the class
        new_instance_address = self.compile_new_instance(address, init_function, mfunction)

        encoded_pointer = new_instance_address.to_bytes(8, "little")
        self.class_offset = self.write_data(encoded_pointer, self.class_offset)

        return tagged_address

    # Allocate an object with the given value
    # Return the address of the encoded object
    def allocate_object(self, value):

        # Must return an address
        size = len(bytes(value))

        # SIZE    32 bits |      VALUE
        encoded_size = size.to_bytes(32, "little")

        # Save the address of this object
        address = self.get_current_data_address()

        # Write the size, then the value
        self.data_offset = self.write_data(encoded_size, self.data_offset)

        self.data_offset = self.write_data(value, self.data_offset)

        return address

    # Compile code to make a new instance of a class.
    # A pointer to this code is returned
    # class_address : The non-tagged address of the class
    # init_function : if any, the Function object for the __init__ definition
    # class_function : The englobing class-Function definition
    def compile_new_instance(self, class_address, init_function, class_function):
        code_address = self.get_current_address()

        # Move the object's address inside rax
        self.runtime_allocator.allocate_instance(class_address, init_function, class_function)

        return code_address

    # Create python array interface from C allocated arrays
    def python_arrays(self):

        self.code_section = stub_handler.ffi.buffer(self.code_buffer, self.code_size)

        self.data_section = stub_handler.ffi.buffer(self.data_buffer, self.data_size)

    def get_current_address(self):
        return stub_handler.lib.get_address(self.code_buffer, self.code_offset)

    # Return the next address for storing an instruction
    def get_current_data_address(self):
        return stub_handler.lib.get_address(self.data_buffer, self.data_offset)

    # Return the next address for storing a class definition
    def get_current_class_address(self):
        return stub_handler.lib.get_address(self.data_buffer, self.class_offset)

    # Encode and store in memory one instruction
    # instruction : The asm.Instruction to encode
    # mfunction : Current compiled function
    def encode(self, instruction, mfunction=None):
        encoded = instruction.encode()

        if mfunction.allocator is not None:
            mfunction.allocator.versioning.current_version().new_instruction(instruction)

        # Store each byte in memory and update code_offset
        self.code_offset = self.write_instruction(encoded, self.code_offset)

    # Encode one instruction for a stub, will be put in a special section of code
    # Return the address of the beginning of the instruction in the bytearray
    def encode_stub(self, instruction):
        encoded = instruction.encode()

        stub_offset_beginning = self.stub_offset

        # Now, put the instruction in the end of the code section
        self.stub_offset = self.write_instruction(encoded, self.stub_offset)

        return stub_handler.lib.get_address(stub_handler.ffi.from_buffer(self.code_section), stub_offset_beginning)

    # Write one instruction in the code section at a specified offset
    # Return the new offset to be saved
    def write_instruction(self, encoded, offset):
        for val in encoded:
            self.code_section[offset] = val.to_bytes(1, 'big')
            offset = offset + 1
        return offset

    # Write a data in the data section
    def write_data(self, encoded, offset):
        for val in encoded:
            self.data_section[offset] = val.to_bytes(1, 'big')
            offset = offset + 1
        return offset

    # Disassemble the compiled assembly code
    def disassemble_asm(self):
        if not self.jitcompiler.interpreter.args.asm:
            return

        bytes_cs = bytes(self.code_section)

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for i in md.disasm(bytes_cs, self.code_address, self.code_offset):
            print("\t0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

        print("\n")


# Handle the runtime allocation
# Maintain a pointer to the next free zone
class RuntimeAllocator:
    def __init__(self, global_allocator):
        self.global_allocator = global_allocator

        global_allocator.runtime_allocator = self

        # The register where the allocation pointer is stored
        self.register_allocation = asm.r15

    # Compile a sequence of code to initialize the allocation pointer
    def init_allocation_pointer(self):
        # We need to put a value inside the designated register
        address_beginning = self.global_allocator.data_address + self.global_allocator.runtime_offset

        encoded = asm.MOV(self.register_allocation, address_beginning).encode()
        self.global_allocator.code_offset = self.global_allocator.write_instruction(encoded, self.global_allocator.code_offset)

    # Allocate an object with a given size and return the tagged address in a register
    def allocate_object_with_size(self, size):
        pass

    # Allocate an Object and return its pointer
    # The code must follow the calling convention and clean the stack before returning
    # class_adress : the address of the class
    # init_function : if an __init__ is defined, its corresponding Function or None if no definition is provided
    # class_function : The englobing class-Function definition
    def allocate_instance(self, class_address, init_function, class_function):
        # Save the address of the initializer definition
        c_buffer = stub_handler.ffi.from_buffer(self.global_allocator.code_section)
        init_code_address = stub_handler.lib.get_address(c_buffer, self.global_allocator.code_offset)

        self.global_allocator.jitcompiler.initializer_addresses[class_function.name] = init_code_address

        instructions = list()

        # Move the next available address into rax to return it
        instructions.append(asm.MOV(asm.rax, self.register_allocation))

        # Construct the header with the size of the object
        size = 2
        instructions.append(asm.MOV(asm.operand.MemoryOperand(asm.r15), size))

        # Put a pointer to the class address in the second field
        instructions.append(asm.MOV(asm.r10, class_address))
        instructions.append(asm.MOV(asm.operand.MemoryOperand(self.register_allocation + 8), asm.r10))

        # Increment the allocation pointer
        instructions.append(asm.ADD(self.register_allocation, 8*5))

        # Finally, tag the address inside rax
        tag_instructions = self.global_allocator.jitcompiler.tags.tag_object_asm(asm.rax)

        instructions.extend(tag_instructions)

        # Now call the __init__() method of the class if any
        # TODO: handle __init__ with more than 1 parameters
        if init_function is not None:
            init_offset = 4

            # Save the return address of the current call
            instructions.append(asm.POP(asm.rbx))

            # Saving parameter
            instructions.append(asm.POP(asm.r8))

            # Depop the class address
            instructions.append(asm.ADD(asm.registers.rsp, 8))

            # TODO: problem stack size
            instructions.append(asm.PUSH(asm.rbx))

            # Push back object and parameters
            instructions.append(asm.PUSH(asm.rax))
            instructions.append(asm.PUSH(asm.r8))

            # Make the call to init
            instructions.append(asm.ADD(asm.r10, 8*init_offset))
            instructions.append(asm.CALL(asm.operand.MemoryOperand(asm.r10)))

        # Saving return address in a register
        instructions.append(asm.POP(asm.rbx))

        instructions.append(asm.JMP(asm.rbx))

        offset = self.global_allocator.code_offset
        for i in instructions:
            offset = self.global_allocator.write_instruction(i.encode(), offset)

        self.global_allocator.code_offset = offset

