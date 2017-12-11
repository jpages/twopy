'''
This module contains the JIT compiler
'''

import peachpy
import sys

import ctypes
import mmap

# rename for better code visibility
import peachpy.x86_64 as asm
from peachpy.common.function import active_function

from . import stub_handler
import interpreter.simple_interpreter

# Handle all operations related to JIT compilation of the code
class JITCompiler:

    # For now keep a SimpleInterpreter instance
    def __init__(self, simpleinterpreter):
        self.interpreter = simpleinterpreter

        self.stub_handler = stub_handler.StubHandler(self)
        stub_handler.jitcompiler_instance = self

        # Mapping between functions and their code
        self.dict_compiled_functions = {}

        # Dictionary between stub ids and blocks to compile
        self.stub_dictionary = {}

    # Compile the function  in parameter to binary code
    # return the code instance
    def compile_function(self, function, inter):

        allocator = Allocator(function)
        function.allocator = allocator

        allocator.arguments_loading()

        # Start the compilation of the first basic block
        self.compile_instructions(function, function.start_basic_block)

        # Load the function
        allocator.load()

        # TODO: just a test
        if function.name != "main":
            print("Call to the function with the parameter 5 : " + str(allocator(5)))

    # Compile all instructions to binary code
    # mfunction : the simple_interpreter.Function object
    # block : The BasicBlock to compile
    def compile_instructions(self, mfunction, block):

        allocator = mfunction.allocator

        for i in range(len(block.instructions)):

            instruction = block.instructions[i]
            # big dispatch for all instructions
            if isinstance(instruction, interpreter.simple_interpreter.POP_TOP):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.ROT_TWO):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.ROT_THREE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.DUP_TOP):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.DUP_TOP_TWO):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.NOP):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.UNARY_POSITIVE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.UNARY_NEGATIVE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.UNARY_NOT):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.UNARY_INVERT):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_MATRIX_MULTIPLY):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_MATRIX_MULTIPLY):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_POWER):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_MULTIPLY):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_MODULO):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_ADD):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_SUBTRACT):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_SUBSCR):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_FLOOR_DIVIDE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_TRUE_DIVIDE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_FLOOR_DIVIDE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_TRUE_DIVIDE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.GET_AITER):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.GET_ANEXT):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BEFORE_ASYNC_WITH):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_ADD):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_SUBTRACT):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_MULTIPLY):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_MODULO):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_SUBSCR):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_SUBSCR):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_LSHIFT):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_RSHIFT):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_AND):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_XOR):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_OR):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_POWER):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.GET_ITER):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.GET_YIELD_FROM_ITER):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.PRINT_EXPR):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_BUILD_CLASS):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.YIELD_FROM):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.GET_AWAITABLE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_LSHIFT):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_RSHIFT):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_AND):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_XOR):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_OR):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BREAK_LOOP):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.WITH_CLEANUP_START):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.WITH_CLEANUP_FINISH):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.RETURN_VALUE):
                allocator.encode(asm.RETURN())
            elif isinstance(instruction, interpreter.simple_interpreter.IMPORT_STAR):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_ANNOTATIONS):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.YIELD_VALUE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.POP_BLOCK):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.END_FINALLY):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.POP_EXCEPT):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.HAVE_ARGUMENT):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_NAME):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_NAME):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.UNPACK_SEQUENCE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.FOR_ITER):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.UNPACK_EX):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_ATTR):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_ATTR):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_GLOBAL):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_GLOBAL):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_CONST):
                print("Instruction compiled " + str(instruction))

                # We need to perform an allocation here
                value = block.function.consts[instruction.arguments]
                block.function.allocator.allocate_const(value)

                print("The value is now allocated")
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_NAME):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_TUPLE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_LIST):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_SET):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_MAP):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_ATTR):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.COMPARE_OP):
                print("Instruction compiled " + str(instruction))

                # COMPARE_OP can't be the last instruction of the block
                next_instruction = block.instructions[i+1]

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
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.IMPORT_FROM):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.JUMP_FORWARD):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.JUMP_IF_FALSE_OR_POP):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.JUMP_IF_TRUE_OR_POP):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.JUMP_ABSOLUTE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.POP_JUMP_IF_FALSE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.POP_JUMP_IF_TRUE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_GLOBAL):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.CONTINUE_LOOP):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_LOOP):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_EXCEPT):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_FINALLY):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_FAST):
                print("Instruction compiled " + str(instruction))

                # Load the value and put it onto the stack
                varname = block.function.varnames[instruction.arguments]
                allocator.encode(asm.PUSH(mfunction.allocations[varname]))

            elif isinstance(instruction, interpreter.simple_interpreter.STORE_FAST):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_FAST):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_ANNOTATION):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.RAISE_VARARGS):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.CALL_FUNCTION):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.MAKE_FUNCTION):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_SLICE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_CLOSURE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_DEREF):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_DEREF):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_DEREF):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.CALL_FUNCTION_KW):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.CALL_FUNCTION_EX):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_WITH):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.EXTENDED_ARG):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.LIST_APPEND):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.SET_ADD):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.MAP_ADD):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_CLASSDEREF):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_LIST_UNPACK):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_MAP_UNPACK):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_MAP_UNPACK_WITH_CALL):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_TUPLE_UNPACK):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_SET_UNPACK):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_ASYNC_WITH):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.FORMAT_VALUE):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_CONST_KEY_MAP):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_STRING):
                print("Instruction not compiled " + str(instruction))
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_TUPLE_UNPACK_WITH_CALL):
                print("Instruction not compiled " + str(instruction))

    # Compare operators
    compare_operators = ('<', '<=', '==', '!=', '>', '>=', 'in',
    'not in', 'is', 'is not', 'exception match', 'BAD')

    # Functions used to compile a comparison then a jump after (a if)
    # mfunction : Current compiled function
    # instruction : Current python Bytecode instruction
    # next_instruction : The following instruction
    def compile_cmp_POP_JUMP_IF_FALSE(self, mfunction, instruction, next_instruction):
        self.compile_cmp_beginning(mfunction)

        # not first < second -> first >= second
        true_label = asm.Label("true_block")
        if instruction.arguments == 0:
            false_label = asm.Label("false_block")

            # The stubs must be compiled before the jumps

            # Jump to stubs
            mfunction.allocator.encode(asm.JGE(true_label))
            mfunction.allocator.encode(asm.JMP(false_label))

            # TODO: call compile_stub two times here
            mfunction.allocator.encode(asm.PUSH(5))

            # Get the two following blocks
            jump_block = None
            notjump_block = None

            # Locate the target of the jump in next basic blocks
            for block in instruction.block.next:
                # If we need to make the jump
                if block.instructions[0].offset == next_instruction.arguments:
                    jump_block = block
                else:
                    # Continue the execution in the second block
                    notjump_block = block

            # Compile a stub for each branch
            mfunction.allocator.encode(asm.LABEL(true_label))
            self.stub_handler.compile_stub(mfunction, id(jump_block))
            self.stub_dictionary[id(jump_block)] = jump_block

            # And update the dictionary of ids and blocks
            mfunction.allocator.encode(asm.LABEL(false_label))
            self.stub_handler.compile_stub(mfunction, id(notjump_block))
            self.stub_dictionary[id(notjump_block)] = notjump_block

        elif instruction.arguments == 1:
            pass
        else:
            pass

    def compile_cmp_beginning(self, mfunction):
        # Put both operand into registers
        second_register = asm.rax
        first_register = asm.rbx
        mfunction.allocator.encode(asm.POP(second_register))
        mfunction.allocator.encode(asm.POP(first_register))
        mfunction.allocator.encode(asm.CMP(second_register, first_register))


# Allocate and handle the compilation of a function
class Allocator:
    def __init__(self, function):
        self.function = function

        # # Mapping between variables names and memory
        self.function.allocations = {}

        # Where the code is allocated
        self.code_section = bytearray(100)

        # Where data are allocated
        self.data_section = bytearray(100)

        # The offset in code_section where the code can be allocated
        self.code_offset = 0

        # Future code address when loaded
        self.code_address = None

        # Future data address when loaded
        self.data_address = None


    # Compile the loading of arguments of the function
    def arguments_loading(self):
        # FIXME: for now all parameters are 64 bits integers
        # Create registers for each argument
        arguments_registers = []
        for i in range(self.function.argcount):
            # Make a proper register allocation
            arguments_registers.append(asm.rax)

        # Mapping between variables names and memory
        self.function.allocations = {}

        # Arguments should be on the stack
        for i in range(self.function.argcount):
            # Put each argument into a register
            instruction = asm.POP(arguments_registers[i])

            self.function.allocations[self.function.varnames[i]] = arguments_registers[i]
            self.encode(instruction)

    # Allocate a value and update the environment, this function create an instruction to store the value
    # value : the value to allocate
    def allocate_const(self, value):
        # Depending of the type of the value, do different things

        if isinstance(value, int):
            # Put the integer value on the stack
            self.encode(asm.PUSH(value))

            # TODO: handle other types

    # Encode and store in memory one instruction
    # instruction = the asm.Instruction to encode
    def encode(self, instruction):
        encoded = instruction.encode()

        # Store each byte in memory and update code_offset
        for val in encoded:
            self.code_section[self.code_offset] = val
            self.code_offset = self.code_offset + 1

    # Make the code executable
    def load(self):
        self.code_size = len(self.code_section)
        self.data_size = len(self.data_section)

        osname = sys.platform.lower()

        # For now, just support Unix platforms
        if osname == "darwin" or osname.startswith("linux"):

            # Get the C library
            if osname == "darwin":
                libc = ctypes.cdll.LoadLibrary("libc.dylib")
            else:
                libc = ctypes.cdll.LoadLibrary("libc.so.6")

            # void* mmap(void* addr, size_t len, int prot, int flags, int fd, off_t offset)
            mmap_function = libc.mmap
            mmap_function.restype = ctypes.c_void_p
            mmap_function.argtype = [ctypes.c_void_p, ctypes.c_size_t,
                                     ctypes.c_int, ctypes.c_int,
                                     ctypes.c_int, ctypes.c_size_t]

            # int munmap(void* addr, size_t len)
            munmap_function = libc.munmap
            munmap_function.restype = ctypes.c_int
            munmap_function.argtype = [ctypes.c_void_p, ctypes.c_size_t]

            def munmap(address, size):
                munmap_result = munmap_function(ctypes.c_void_p(address), size)
                assert munmap_result == 0

            # Allocate code segment
            code_address = mmap_function(None, self.code_size,
                                         mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
                                         mmap.MAP_ANON | mmap.MAP_PRIVATE,
                                         -1, 0)
            if code_address == -1:
                raise OSError("Failed to allocate memory for code segment")
            self.code_address = code_address

            if self.data_size > 0:
                # Allocate data segment
                data_address = mmap_function(None, self.data_size,
                                             mmap.PROT_READ | mmap.PROT_WRITE,
                                             mmap.MAP_ANON | mmap.MAP_PRIVATE,
                                             -1, 0)
                if data_address == -1:
                    raise OSError("Failed to allocate memory for data segment")
                self.data_address = data_address

            print("Code address " + str(self.code_address))

            # Copy the code to this location
            self.relocation()

        # Create a pointer to be able to call this function directly in python
        self.create_function_pointer()

    # Relocate the code and data to the newly areas
    def relocation(self):
        ctypes.memmove(self.code_address,
                       ctypes.c_char_p(bytes(self.code_section)),
                       len(self.code_section))

        ctypes.c_char_p
        ctypes.memmove(self.data_address,
                       ctypes.c_char_p(bytes(self.data_section)),
                       len(self.data_section))


    # Create a pointer to the compiled function
    def create_function_pointer(self):
        # TODO: Adapt types to the correct ones
        #result_type = None if function.result_type is None else function.result_type.as_ctypes_type
        #argument_types = [arg.c_type.as_ctypes_type for arg in function.arguments]

        self.function_type = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64)
        self.function_pointer = self.function_type(self.code_address)

    # Call the compiled function
    def __call__(self, *args):
        return self.function_pointer(*args)
