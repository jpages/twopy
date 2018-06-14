'''
This module contains code relative to memory allocation and garbage collection
'''

# ASM disassembly
import capstone
import mmap

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
                                                          mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
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
    # TODO: get an indication on the size (number of methods) of the class
    def allocate_class(self):

        # TODO: Try to know the size of the structure we need to allocate

        # Save the address of this object
        address = self.get_current_data_address()

        # TODO: for the test consider only 4 values inside the class
        size = 4 * 64

        # SIZE    64 bits |      Array of pointers
        encoded_size = size.to_bytes(64, "little")

        # Write the size, then the value
        self.data_offset = self.write_data(encoded_size, self.data_offset)

        # Put the tag to indicate a memory object
        tagged_address = self.jitcompiler.tags.tag_object(address)

        return tagged_address

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
    # instruction = the asm.Instruction to encode
    def encode(self, instruction, function):
        encoded = instruction.encode()

        if function.allocator != None:
            function.allocator.versioning.current_version().new_instruction(instruction)

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
            #Print labels
            #if i.address in self.jump_labels:
            #    print(str(self.jump_labels[i.address]) + " " + str(hex(i.address)))
            print("\t0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

        print("\n")

