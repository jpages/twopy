'''
This module contains code relative to memory allocation and garbage collection
'''

# ASM disassembly
import capstone
import mmap

import peachpy.x86_64 as asm

from . import stub_handler


# Handle allocation of the general code section
class GlobalAllocator:
    def __init__(self, jitcompiler):
        self.jitcompiler = jitcompiler

        # Size of the code section
        self.code_size = 20000

        # Size of the data section
        self.data_size = 500

        # The next free zone in the data section
        self.data_offset = 0

        # The offset in code_section where the code can be allocated
        self.code_offset = 0

        # The stub pointer is in the end of the code section
        self.stub_offset = 15000

        # Future code and data sections, will be allocated in C
        self.code_section = None
        self.data_section = None

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
        code_address = self.jitcompiler.mmap_function(None, self.code_size,
                                                      mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
                                                      mmap.MAP_ANON | mmap.MAP_PRIVATE,
                                                      -1, 0)

        if code_address == -1:
            raise OSError("Failed to allocate memory for code segment")
        self.code_address = code_address

        if self.data_size > 0:
            # Allocate data segment
            data_address = self.jitcompiler.mmap_function(None, self.data_size,
                                                          mmap.PROT_READ | mmap.PROT_WRITE,
                                                          mmap.MAP_ANON | mmap.MAP_PRIVATE,
                                                          -1, 0)
            if data_address == -1:
                raise OSError("Failed to allocate memory for data segment")
            self.data_address = data_address

        # Create manipulable python arrays for these two sections
        self.python_arrays()

    # Allocate an object with the given value
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

    # Allocate a new blank class object to be filled later
    # Each word of a class is 64 bits
    # | header | new_instance | method1 | method2 | ...
    # The second field is a pointer to the new_instance code for this class
    # TODO: get an indication on the size (number of methods) of the class
    def allocate_class(self):
        # TODO: Try to know the size of the structure we need to allocate

        # Save the address of this object
        address = self.get_current_data_address()

        # TODO: for the test consider only 4 values inside the class
        size = 4 * 64

        # SIZE    64 bits |      Array of pointers
        encoded_size = size.to_bytes(8, "little")

        # Write the size
        self.data_offset = self.write_data(encoded_size, self.data_offset)

        # Put the tag to indicate a memory object
        tagged_address = self.jitcompiler.tags.tag_object(address)

        # Now we need to store the pointer to the new instance code inside the class
        new_instance_address = self.compile_new_instance(address)

        encoded_pointer = new_instance_address.to_bytes(8, "little")
        self.data_offset = self.write_data(encoded_pointer, self.data_offset)

        return tagged_address

    # Compile code to make a new instance of a class.
    # A pointer to this code is returned
    # class_address : The non-tagged address of the class
    def compile_new_instance(self, class_address):
        code_address = self.get_current_address()

        # Move the object's address inside rax
        self.runtime_allocator.allocate_instance(class_address)

        return code_address

    # Create python array interface from C allocated arrays
    def python_arrays(self):

        addr = stub_handler.ffi.cast("char*", self.code_address)
        self.code_section = stub_handler.ffi.buffer(addr, self.code_size)

        addr = stub_handler.ffi.cast("char*", self.data_address)
        self.data_section = stub_handler.ffi.buffer(addr, self.data_size)

    # Return the next address for storing an instruction
    def get_current_address(self):
        return stub_handler.lib.get_address(stub_handler.ffi.from_buffer(self.code_section), self.code_offset)

    # Return the next address for storing an instruction
    def get_current_data_address(self):
        return stub_handler.lib.get_address(stub_handler.ffi.from_buffer(self.data_section), self.data_offset)

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

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for i in md.disasm(bytes(self.code_section), self.code_address):
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
        address_beginning = self.global_allocator.data_address + 256

        encoded = asm.MOV(self.register_allocation, address_beginning).encode()
        self.global_allocator.code_offset = self.global_allocator.write_instruction(encoded, self.global_allocator.code_offset)

    # Allocate an object with a given size and return the tagged address in a register
    def allocate_object_with_size(self, size):
        pass

    # Allocate an Object and return its pointer
    # The code must follow the calling convention and clean the stack before returning
    # TODO: If this class has a definition for __init__() compile it
    def allocate_instance(self, class_address):
        instructions = []

        instructions.append(asm.INT(3))

        # Move the next available address into rax to return it
        instructions.append(asm.MOV(asm.rax, self.register_allocation))

        # Construct the header with the size of the object
        size = 2
        instructions.append(asm.MOV(asm.operand.MemoryOperand(asm.r15), size))

        # Put a pointer to the class address in the second field
        instructions.append(asm.MOV(asm.r10, class_address))
        instructions.append(asm.MOV(asm.operand.MemoryOperand(self.register_allocation + 8), asm.r10))

        # Increment the allocation pointer
        instructions.append(asm.ADD(self.register_allocation, 8*2))

        # Finally, tag the address inside rax before returning
        tag_instructions = self.global_allocator.jitcompiler.tags.tag_object_asm(asm.rax)

        instructions.extend(tag_instructions)
        instructions.append(asm.POP(asm.rbx))
        # TODO: clean the stack from __init__() parameters here
        instructions.append(asm.JMP(asm.rbx))

        offset = self.global_allocator.code_offset
        for i in instructions:
            offset = self.global_allocator.write_instruction(i.encode(), offset)

        self.global_allocator.code_offset = offset

