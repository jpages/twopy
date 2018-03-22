'''
This module contains the JIT compiler
'''

import peachpy
import sys

# ASM disassembly
import capstone

import ctypes
import mmap
import copy

# rename for better code visibility
import peachpy.x86_64 as asm

from . import stub_handler
import frontend
from . import objects
import interpreter.simple_interpreter


# Handle all operations related to JIT compilation of the code
class JITCompiler:
    # For now keep a SimpleInterpreter instance
    def __init__(self, simpleinterpreter, maincode):
        self.interpreter = simpleinterpreter

        self.stub_handler = stub_handler.StubHandler(self)
        stub_handler.jitcompiler_instance = self

        # Mapping between functions and their code
        self.dict_compiled_functions = {}

        # Dictionary between constant ids and const values
        self.consts = {}

        # Load C library and create wrappers for python
        self.load_c_library()

        # Main CodeObject
        self.maincode = maincode

        # Main module
        self.mainmodule = self.interpreter.mainmodule

        # Tagging objects
        self.tags = objects.TagHandler()

    # Main function called by the launcher
    def execute(self):
        self.start()

    # Start the execution
    def start(self):
        # Start by compiling standard library
        self.compile_std_lib()

        # Generate the main function and recursively other functions in module
        self.interpreter.generate_function(self.maincode, "main", self.mainmodule, True)

    # Compile the standard library
    def compile_std_lib(self):

        library_code = frontend.compiler.compile("jit/standard_library.py", self.interpreter.args)

        # Force the compilation of std functions
        stdlib_function = self.interpreter.generate_function(library_code, "std_lib", self.mainmodule, True)
        self.compile_function(stdlib_function)

    # Compile a standard function
    def compile_std_function(self, mfunction):

        # For now we just have the print here
        if mfunction.name == "twopy_print":

            # Make a call to C for the print

            # Move the parameter inside rdi to respect the calling convention
            mfunction.allocator.encode(asm.MOV(asm.rdi, mfunction.allocator.get_local_variable(0, mfunction.start_basic_block)))

            # Move the C-print address inside r9
            addr = int(stub_handler.ffi.cast("intptr_t", stub_handler.ffi.addressof(stub_handler.lib, "twopy_library_print_integer")))
            mfunction.allocator.encode(asm.MOV(asm.r9, addr))

            # The return instruction will clean the stack
            mfunction.allocator.encode(asm.CALL(asm.r9))

            # The return value is in rax

            # Saving return address in a register
            mfunction.allocator.encode(asm.POP(asm.rbx))

            # Clean the stack and remove parameters on this call
            for i in range(0, mfunction.argcount + 1):
                # Remove print parameters
                mfunction.allocator.encode(asm.POP(asm.r10))

            # Finally returning by jumping
            mfunction.allocator.encode(asm.JMP(asm.rbx))

            stub_handler.primitive_addresses["print"] = mfunction.allocator.code_address
        else:
            print("Not yet implemented")

    # Compile the function  in parameter to binary code
    # return the code instance
    def compile_function(self, mfunction):
        try:
            mfunction.allocator
            return
        except AttributeError:

            if self.interpreter.args.verbose:
                print("Instructions in function " + str(mfunction))
                for i in mfunction.all_instructions:
                    print("\t " + str(i))

            # Create a versioning handler for the function
            versioning = Versioning(mfunction)

            self.current_function = mfunction
            self.current_block = mfunction.start_basic_block

            # Try to access the attribute allocator of the function
            allocator = Allocator(mfunction, self, versioning)
            mfunction.allocator = allocator

            # Special case for
            if mfunction.name in stub_handler.twopy_primitives:
                self.compile_std_function(mfunction)
            else:
                # Start the compilation of the first basic block
                self.compile_instructions(mfunction, mfunction.start_basic_block)

            # Associate this function with its address
            self.dict_compiled_functions[mfunction] = allocator.code_address + allocator.prolog_size

            if mfunction.name == "main" or mfunction.name == "std_lib":
                # Call the main with a random value
                str(allocator(42))

    # Compile all instructions to binary code
    # mfunction : the simple_interpreter.Function object
    # block : The BasicBlock to compile
    # index : Start the compilation from an index in the block, default 0
    def compile_instructions(self, mfunction, block, index=0):

        allocator = mfunction.allocator

        # Do not compile an already compiled block, except if index is set
        if block.compiled and index == 0:
            return block.first_offset

        # Force the creation of a block
        allocator.versioning.current_version().get_context_for_block(block)
        self.current_block = block

        # Offset of the first instruction compiled in the block
        return_offset = 0

        for i in range(index, len(block.instructions)):
            # If its the first instruction of the block, save its offset
            if i == 0:
                return_offset = allocator.code_offset

            instruction = block.instructions[i]
            # big dispatch for all instructions
            if isinstance(instruction, interpreter.simple_interpreter.POP_TOP):

                # Jut discard the TOS value
                allocator.encode(asm.POP(asm.r10))
            elif isinstance(instruction, interpreter.simple_interpreter.ROT_TWO):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.ROT_THREE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.DUP_TOP):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.DUP_TOP_TWO):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.NOP):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.UNARY_POSITIVE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.UNARY_NEGATIVE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.UNARY_NOT):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.UNARY_INVERT):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_MATRIX_MULTIPLY):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_MATRIX_MULTIPLY):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_POWER):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_MULTIPLY):

                # Pop two values inside registers
                allocator.encode(asm.POP(asm.r9))
                allocator.encode(asm.POP(asm.r8))

                # Untag the value to not duplicate the tag
                ins = self.tags.untag_asm(asm.r8)
                allocator.encode(ins)

                # Make the sub and push the results
                allocator.encode(asm.IMUL(asm.r8, asm.r9))
                allocator.encode(asm.PUSH(asm.r8))

            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_MODULO):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_ADD):

                #TODO: ensure that this operator wasn't redefined
                self.tags.binary_operation("add", mfunction, block, i+1)
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_SUBTRACT):

                #TODO: ensure that this operator wasn't redefined
                self.tags.binary_operation("sub", mfunction, block, i+1)
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_SUBSCR):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_FLOOR_DIVIDE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_TRUE_DIVIDE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_FLOOR_DIVIDE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_TRUE_DIVIDE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.GET_AITER):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.GET_ANEXT):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BEFORE_ASYNC_WITH):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_ADD):

                allocator.encode(asm.POP(asm.r9))

                # Perform the operation on the stack
                allocator.encode(asm.ADD(asm.operand.MemoryOperand(asm.registers.rsp), asm.r9))

            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_SUBTRACT):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_MULTIPLY):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_MODULO):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_SUBSCR):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_SUBSCR):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_LSHIFT):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_RSHIFT):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_AND):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_XOR):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_OR):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_POWER):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.GET_ITER):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.GET_YIELD_FROM_ITER):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.PRINT_EXPR):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_BUILD_CLASS):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.YIELD_FROM):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.GET_AWAITABLE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_LSHIFT):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_RSHIFT):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_AND):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_XOR):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_OR):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BREAK_LOOP):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.WITH_CLEANUP_START):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.WITH_CLEANUP_FINISH):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.RETURN_VALUE):

                if mfunction.name == "fibR":
                    allocator.encode(asm.INT(3))

                # Pop the current TOS (the value)
                allocator.encode(asm.POP(asm.rax))

                # Saving return address in a register
                allocator.encode(asm.POP(asm.rbx))

                # Keep the stack size correct
                for i in range(0, instruction.block.function.argcount + 1):
                    allocator.versioning.current_version().get_context_for_block(block).increase_stack_size()

                # Remove arguments from the stack
                to_depop = 8*(instruction.block.function.argcount+1)
                allocator.encode(asm.ADD(asm.registers.rsp, to_depop))

                # Finally returning by jumping
                allocator.encode(asm.JMP(asm.rbx))

            elif isinstance(instruction, interpreter.simple_interpreter.IMPORT_STAR):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_ANNOTATIONS):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.YIELD_VALUE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.POP_BLOCK):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.END_FINALLY):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.POP_EXCEPT):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.HAVE_ARGUMENT):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_NAME):
                # Store a name in the local environment
                allocator.encode(asm.MOV(asm.r9, allocator.data_address))

                # Write TOS at the instruction.arguments index in data_section
                allocator.encode(asm.POP(asm.r10))

                # Offset of the instruction's argument + r9 value
                memory_address = asm.r9 + (64*instruction.arguments)
                allocator.encode(asm.MOV(asm.operand.MemoryOperand(memory_address), asm.r10))

            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_NAME):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.UNPACK_SEQUENCE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.FOR_ITER):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.UNPACK_EX):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_ATTR):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_ATTR):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_GLOBAL):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_GLOBAL):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_CONST):
                # We need to perform an allocation here
                value = block.function.consts[instruction.arguments]
                block.function.allocator.allocate_const(instruction, value)

            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_NAME):
                name = instruction.function.names[instruction.arguments]

                # We are loading something from builtins
                if name in stub_handler.primitive_addresses:
                    function_address = stub_handler.primitive_addresses[name]

                    allocator.encode(asm.MOV(asm.r9, function_address))
                    allocator.encode(asm.PUSH(asm.r9))
                else:
                    # Load a name (a variable) in the local environment
                    allocator.encode(asm.MOV(asm.r9, allocator.data_address))

                    # Offset of the instruction's argument + r9 value
                    memory_address = asm.r9 + (64*instruction.arguments)
                    allocator.encode(asm.MOV(asm.r10, asm.operand.MemoryOperand(memory_address)))

                    allocator.encode(asm.PUSH(asm.r10))

            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_TUPLE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_LIST):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_SET):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_MAP):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_ATTR):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.COMPARE_OP):

                # COMPARE_OP can't be the last instruction of the block
                next_instruction = block.instructions[i + 1]

                if isinstance(next_instruction, interpreter.simple_interpreter.JUMP_IF_FALSE_OR_POP):
                    self.compile_cmp_JUMP_IF_FALSE_OR_POP(mfunction, instruction, next_instruction)
                elif isinstance(next_instruction, interpreter.simple_interpreter.JUMP_IF_TRUE_OR_POP):
                    self.compile_cmp_JUMP_IF_TRUE_OR_POP(mfunction, instruction, next_instruction)
                elif isinstance(next_instruction, interpreter.simple_interpreter.POP_JUMP_IF_FALSE):
                    self.compile_cmp_POP_JUMP_IF_FALSE(mfunction, instruction, next_instruction)
                elif isinstance(next_instruction, interpreter.simple_interpreter.POP_JUMP_IF_TRUE):
                    self.compile_cmp_POP_JUMP_IF_TRUE(mfunction, instruction, next_instruction)
                else:
                    # General case, we need to put the value on the stack
                    self.compile_cmp(instruction)

                # We already compiled the next instruction which is a branch, the block is fully compiled now
                return
            elif isinstance(instruction, interpreter.simple_interpreter.IMPORT_NAME):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.IMPORT_FROM):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.JUMP_FORWARD):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.JUMP_IF_FALSE_OR_POP):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.JUMP_IF_TRUE_OR_POP):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.JUMP_ABSOLUTE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.POP_JUMP_IF_FALSE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.POP_JUMP_IF_TRUE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_GLOBAL):

                name = mfunction.names[instruction.arguments]

                element = None
                # Lookup in the global environment
                if name in self.interpreter.global_environment:
                    element = self.interpreter.global_environment[name]
                else:
                    # Lookup in its module to find a name
                    element = mfunction.module.lookup(name, False)

                # Assume we have a function here for now
                allocator.encode(asm.MOV(asm.r9, self.dict_compiled_functions[element]))
                allocator.encode(asm.PUSH(asm.r9))

            elif isinstance(instruction, interpreter.simple_interpreter.CONTINUE_LOOP):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_LOOP):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_EXCEPT):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_FINALLY):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_FAST):

                # Load the value and put it onto the stack
                allocator.encode(asm.PUSH(allocator.get_local_variable(instruction.arguments, block)))

            elif isinstance(instruction, interpreter.simple_interpreter.STORE_FAST):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_FAST):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_ANNOTATION):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.RAISE_VARARGS):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.CALL_FUNCTION):

                # Save the function address in r9
                allocator.encode(asm.MOV(asm.r9, asm.operand.MemoryOperand(asm.registers.rsp+8*instruction.arguments)))

                # The return instruction will clean the stack
                allocator.encode(asm.CALL(asm.r9))

                for i in range(0, instruction.block.function.argcount + 1):
                    allocator.versioning.current_version().get_context_for_block(block).decrease_stack_size()

                # The return value is in rax, push it back on the stack
                allocator.encode(asm.PUSH(asm.rax))

            elif isinstance(instruction, interpreter.simple_interpreter.MAKE_FUNCTION):

                nbargs = 2 # The name and the code object

                free_variables = None
                if (instruction.arguments & 8) == 8:
                    # Making a closure, tuple of free variables
                    pass

                if (instruction.arguments & 4) == 4:
                    # Annotation dictionnary
                    pass

                if (instruction.arguments & 2) == 2:
                    # keyword only default arguments
                    pass

                if (instruction.arguments & 1) == 1:
                    # default arguments
                    pass

                # TODO : temporary, the return address will be after the call to the stub
                address = stub_handler.lib.get_address(stub_handler.ffi.from_buffer(allocator.code_section), allocator.code_offset + 13)

                stub_address = self.stub_handler.compile_function_stub(mfunction, nbargs, address)

                allocator.encode(asm.MOV(asm.r10, stub_address))
                allocator.encode(asm.CALL(asm.r10))

                # Discard the two values on the stack
                allocator.encode(asm.POP(asm.r10))
                allocator.encode(asm.POP(asm.r10))

            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_SLICE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_CLOSURE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_DEREF):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_DEREF):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_DEREF):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.CALL_FUNCTION_KW):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.CALL_FUNCTION_EX):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_WITH):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.EXTENDED_ARG):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.LIST_APPEND):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.SET_ADD):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.MAP_ADD):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_CLASSDEREF):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_LIST_UNPACK):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_MAP_UNPACK):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_MAP_UNPACK_WITH_CALL):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_TUPLE_UNPACK):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_SET_UNPACK):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_ASYNC_WITH):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.FORMAT_VALUE):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_CONST_KEY_MAP):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_STRING):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_TUPLE_UNPACK_WITH_CALL):
                pass

        block.compiled = True
        block.first_offset = return_offset

        return return_offset

    # Compare operators
    compare_operators = ('<', '<=', '==', '!=', '>', '>=', 'in',
                         'not in', 'is', 'is not', 'exception match', 'BAD')

    # Functions used to compile a comparison then a jump after (a if)
    # mfunction : Current compiled function
    # instruction : Current python Bytecode instruction
    # next_instruction : The following instruction
    def compile_cmp_POP_JUMP_IF_FALSE(self, mfunction, instruction, next_instruction):
        self.compile_cmp_beginning(mfunction)

        # first < second
        if instruction.arguments == 0:
            # The stubs must be compiled before the jumps
            # Get the two following blocks
            jump_block = None
            notjump_block = None

            # Locate the target of the jump in next basic blocks
            for block in instruction.block.next:
                # If we need to make the jump
                if block.instructions[0].offset == next_instruction.arguments:
                    notjump_block = block
                else:
                    # Continue the execution in the second block
                    jump_block = block

            # Compile stubs for each branch
            self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block)
        # first > second
        elif instruction.arguments == 4:
            # The stubs must be compiled before the jumps
            # Get the two following blocks
            jump_block = None
            notjump_block = None

            # Locate the target of the jump in next basic blocks
            for block in instruction.block.next:
                # If we need to make the jump
                if block.instructions[0].offset == next_instruction.arguments:
                    notjump_block = block
                else:
                    # Continue the execution in the second block
                    jump_block = block

            # Compile stubs for each branch
            self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block)
        else:
            pass

    def compile_cmp_beginning(self, mfunction):
        # Put both operand into registers
        second_register = asm.r8
        first_register = asm.r9
        mfunction.allocator.encode(asm.POP(second_register))
        mfunction.allocator.encode(asm.POP(first_register))
        mfunction.allocator.encode(asm.CMP(first_register, second_register))

    # Define function for code allocation later
    def load_c_library(self):
        osname = sys.platform.lower()

        # For now, just support Unix platforms
        if osname == "darwin" or osname.startswith("linux"):

            # Get the C library
            if osname == "darwin":
                libc = ctypes.cdll.LoadLibrary("libc.dylib")
            else:
                libc = ctypes.cdll.LoadLibrary("libc.so.6")

            # void* mmap(void* addr, size_t len, int prot, int flags, int fd, off_t offset)
            self.mmap_function = libc.mmap
            self.mmap_function.restype = ctypes.c_void_p
            self.mmap_function.argtype = [ctypes.c_void_p, ctypes.c_size_t,
                                     ctypes.c_int, ctypes.c_int,
                                     ctypes.c_int, ctypes.c_size_t]

            # int munmap(void* addr, size_t len)
            self.munmap_function = libc.munmap
            self.munmap_function.restype = ctypes.c_int
            self.munmap_function.argtype = [ctypes.c_void_p, ctypes.c_size_t]

            def munmap(address, size):
                munmap_result = self.munmap_function(ctypes.c_void_p(address), size)
                assert munmap_result == 0

# Allocate and handle the compilation of a function
class Allocator:
    def __init__(self, mfunction, jitcompiler, versioning):
        self.function = mfunction
        self.jitcompiler = jitcompiler
        self.versioning = versioning

        # # Mapping between variables names and memory
        self.function.allocations = {}

        # Size of the code section
        self.code_size = 1000

        # Size of the data section
        self.data_size = 100

        # The next free zone in the data section
        self.data_offset = 0

        # The offset in code_section where the code can be allocated
        # Let some size to encode loading of parameters in the beginning
        self.code_offset = 0

        # The stub pointer is in the end of the code section
        self.stub_offset = 600

        # Future code and data sections, will be allocated in C
        self.code_section = None
        self.data_section = None

        # Future code address
        self.code_address = None

        # Future data address
        self.data_address = None

        # Allocate the code segment in C
        self.allocate_code_segment()

        # If any, the size reserved for the prolog
        self.prolog_size = 0

        # Association between labels and addresses to print them
        self.jump_labels = dict()

        # Compile a prolog only for the main function, other functions don't need that
        if self.function.name == "main":
            self.compile_prolog()

    # Allocate a value and update the environment, this function create an instruction to store the value
    # instruction : The instruction
    # value : the value to allocate
    def allocate_const(self, instruction, value):

        # Bool are considered integers in python, we need to check this first
        if isinstance(value, bool):
            # Tag a boolean
            tvalue = self.jitcompiler.tags.tag_bool(value)
            self.encode(asm.PUSH(tvalue))
        elif isinstance(value, int):
            # Put the integer value on the stack
            tvalue = self.jitcompiler.tags.tag_integer(value)
            self.encode(asm.PUSH(tvalue))
        elif isinstance(value, float):
            # TODO: Encode a float
            pass
        else:
            # For now assume it's consts
            const_object = self.function.consts[instruction.arguments]

            self.encode(asm.MOV(asm.r10, id(const_object)))
            self.encode(asm.PUSH(asm.r10))

            self.jitcompiler.consts[id(const_object)] = const_object

        # TODO: handle other types
        # Depending of the type of the value, do different things

    # Encode and store in memory one instruction
    # instruction = the asm.Instruction to encode
    def encode(self, instruction):
        encoded = instruction.encode()

        self.versioning.current_version().new_instruction(instruction)

        # Store each byte in memory and update code_offset
        self.code_offset = self.write_instruction(encoded, self.code_offset)

    # TODO: to remove
    # Compile a stub in a special area of the code section
    # mstub_handler : StubHandler instance
    # mfunction : current function
    # id_block : id to put in the stub
    def compile_stub(self, mstub_handler, mfunction, id_block):
        return mstub_handler.compile_stub(mfunction, id_block)

    # TODO: to remove
    # Compile a stub to a function
    # mstub_handler : StubHandler instance
    # nbargs : number of parameter for this stub
    # address_after : where to jump after the stub
    def compile_function_stub(self, mstub_handler, nbargs, address_after):

        # Put the number of parameters as the first argument
        self.encode(asm.MOV(asm.rdi, nbargs))

        # The base case, 2 parameter for the call
        if nbargs == 2:
            self.encode(asm.POP(asm.rsi))
            self.encode(asm.POP(asm.rdx))

        return mstub_handler.compile_function_stub(self.function, nbargs, address_after)

    # Encode one instruction for a stub, will be put in a special section of code
    # Return the address of the beginning of the instruction in the bytearray
    def encode_stub(self, instruction):
        encoded = instruction.encode()

        stub_offset_beginning = self.stub_offset

        # Now, put the instruction in the end of the code section
        self.stub_offset = self.write_instruction(encoded, self.stub_offset)

        return stub_handler.lib.get_address(stub_handler.ffi.from_buffer(self.code_section), stub_offset_beginning)

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

        # Create a pointer to be able to call this function directly in python
        self.create_function_pointer()

    # Create python array interface from C allocated arrays
    def python_arrays(self):

        addr = stub_handler.ffi.cast("char*", self.code_address)
        self.code_section = stub_handler.ffi.buffer(addr, self.code_size)

        addr = stub_handler.ffi.cast("char*", self.data_address)
        self.data_section = stub_handler.ffi.buffer(addr, self.data_size)

    # Create a pointer to the compiled function
    def create_function_pointer(self):
        self.function_type = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64)
        self.function_pointer = self.function_type(self.code_address)

    # Get the local variable from the number in parameter
    # argument : number of the variable
    # block : enclosing block for this access
    def get_local_variable(self, argument, block):
        offset = self.versioning.current_version().get_context_for_block(block).get_offset(argument)

        print("Offset " + str(offset))
        self.encode(asm.MOV(asm.r9, asm.operand.MemoryOperand(asm.registers.rsp + offset)))

        return asm.r9

    # Call the compiled function
    def __call__(self, *args):
        #print the asm code
        if self.jitcompiler.interpreter.args.asm:
            self.disassemble_asm()

        # Make the actual call
        return self.function_pointer(*args)

    # Compile a fraction of code to call the correct function with its parameters
    def compile_prolog(self):
        # Save rbp
        self.encode(asm.PUSH(asm.rbp))
        self.encode(asm.MOV(asm.rbp, asm.registers.rsp))

        # Call the function just after this prolog
        # Minus the size of the return and stack's cleaning
        offset = self.code_offset
        self.encode(asm.CALL(asm.operand.RIPRelativeOffset(offset + 1)))

        # Restore the stack
        self.encode(asm.MOV(asm.registers.rsp, asm.rbp))
        self.encode(asm.POP(asm.rbp))

        # Finally return to python
        self.encode(asm.RET())

        self.prolog_size = self.code_offset

    # Write one instruction in the code section at a specified offset
    # Return the new offset to be saved
    def write_instruction(self, encoded, offset):
        for val in encoded:
            self.code_section[offset] = val.to_bytes(1, 'big')
            offset = offset + 1
        return offset

    # Write a data in the data section
    def write_data(self, data):

        self.encode(asm.MOV(asm.r10, stub_handler.lib.get_address(stub_handler.ffi.from_buffer(self.data_section), self.data_offset)))
        self.encode(asm.MOV(asm.operand.MemoryOperand(asm.r10), data))

        self.data_offset = self.data_offset + 1

    # Disassemble the compiled assembly code
    def disassemble_asm(self):
        if not self.jitcompiler.interpreter.args.asm:
            return

        print("Function " + str(self.function.name))
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for i in md.disasm(bytes(self.code_section), self.code_address):
            # Print labels
            if i.address in self.jump_labels:
                print(str(self.jump_labels[i.address]) + " " + str(hex(i.address)))
            print("\t0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

        print("\n")

    # Compiled a call to a C function which print the stack from the stack frame
    def print_stack(self):

        self.encode(asm.MOV(asm.rdi, asm.registers.rsp))
        reg_id = asm.r10

        function_address = int(
            stub_handler.ffi.cast("intptr_t", stub_handler.ffi.addressof(stub_handler.lib, "print_stack")))
        self.encode(asm.MOV(reg_id, function_address))
        self.encode(asm.CALL(reg_id))

    # Compiled a call to a C function which print the data section
    def print_data_section(self):
        self.encode(asm.MOV(asm.rdi, self.data_address))
        self.encode(asm.MOV(asm.rsi, 50))

        reg_id = asm.r10

        function_address = int(
            stub_handler.ffi.cast("intptr_t", stub_handler.ffi.addressof(stub_handler.lib, "print_data_section")))
        self.encode(asm.MOV(reg_id, function_address))
        self.encode(asm.CALL(reg_id))


# Represent all versions of a function
class Versioning:
    def __init__(self, mfunction):
        self.mfunction = mfunction

        # Create the generic version
        self.versions = []
        self.generic_version = None

        self.create_generic_version()

    def create_generic_version(self):
        version = Version(self, Context())
        self.versions.append(version)

        self.generic_version = version

    # Return the version currently compiled
    def current_version(self):
        return self.generic_version


# A particular version
class Version:
    def __init__(self, versioning, context):
        self.versioning = versioning
        #self.context = context

        #self.context.version = self

        # Map between blocks and contexts
        self.context_map = {}

    # Create a context for a given block if needed
    # Return the newly created context or the preexistent one
    def get_context_for_block(self, block):
        if block in self.context_map:
            return self.context_map[block]
        else:
            context = Context()
            context.block = block
            self.context_map[block] = context

            # Copy the previous stack size from a parent block
            for parent in block.previous:
                if parent in self.context_map:
                    # TODO: maybe do something if we have several compiled parent's blocks
                    context.stack_size = self.context_map[parent].stack_size
                    print("Parent stack size " + str(self.context_map[parent].stack_size))

            return context

    # Called each time an instruction is encoded
    def new_instruction(self, instruction):
        # Keep track of the stack size
        if isinstance(instruction, asm.PUSH):
            current_block = stub_handler.jitcompiler_instance.current_block
            self.get_context_for_block(current_block).increase_stack_size()
        elif isinstance(instruction, asm.POP):
            current_block = stub_handler.jitcompiler_instance.current_block
            self.get_context_for_block(current_block).decrease_stack_size()

# Attached to a version, contains information about versioning, stack size etc.
class Context:
    # version The version of the function
    def __init__(self):
        self.version = None

        self.stack_size = 0

        # Dictionary between variables and their types
        self.variable_types = {}

        # Dictionary between variables and their registers
        self.variables_allocation = {}

        # Associated block, if any
        self.block = None

    def increase_stack_size(self):
        self.stack_size += 1

    def decrease_stack_size(self):
        self.stack_size -= 1

    # Get the offset from the rsp for the local variable number nbvariable
    def get_offset(self, nbvariable):
        res = (8 * self.stack_size) + 8*(1 + nbvariable)
        return res

    # Static function to clone a Context
    def clone(other):
        context = Context()

        context.stack_size = other.stack_size
        context.version = other.version
        context.variable_types = copy.deepcopy(other.variable_types)

        return context