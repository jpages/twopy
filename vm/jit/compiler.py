'''
This module contains the JIT compiler
'''

import peachpy
import sys

# ASM disassembly
import capstone

import ctypes
import types
import mmap

# rename for better code visibility
import peachpy.x86_64 as asm
from peachpy.common.function import active_function

from . import stub_handler
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

        # Dictionary between stub ids and blocks to compile
        self.stub_dictionary = {}

        # Dictionary between constant ids and const values
        self.consts = {}

        # Load C library and create wrappers for python
        self.load_c_library()

        # Main CodeObject
        self.maincode = maincode

        # Main module
        self.mainmodule = self.interpreter.mainmodule

    # Main function called by the launcher
    def execute(self):
        self.start()

    # Start the execution
    def start(self):
        # Generate the main function and recursively other functions in module
        self.interpreter.generate_function(self.maincode, "main", self.mainmodule, True)

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

            # Try to access the attribute allocator of the function
            allocator = Allocator(mfunction, self)
            mfunction.allocator = allocator

            allocator.arguments_loading()

            # Start the compilation of the first basic block
            self.compile_instructions(mfunction, mfunction.start_basic_block)

            # Associate this function with its address
            self.dict_compiled_functions[mfunction] = allocator.code_address + allocator.prolog_size

            if mfunction.name == "main" :
                # Call the main with a random value
                str(allocator(42))

    # Compile all instructions to binary code
    # mfunction : the simple_interpreter.Function object
    # block : The BasicBlock to compile
    def compile_instructions(self, mfunction, block):

        allocator = mfunction.allocator

        # Do not compile an already compiled block
        if block.compiled:
            return block.first_offset

        # Offset of the first instruction compiled in the block
        return_offset = 0

        for i in range(len(block.instructions)):

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
                pass

                # Pop two values inside registers
                allocator.encode(asm.POP(asm.r9))
                allocator.encode(asm.POP(asm.r8))

                # Make the sub and push the results
                allocator.encode(asm.IMUL(asm.r8, asm.r9))
                allocator.encode(asm.PUSH(asm.r8))

            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_MODULO):
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_ADD):
                pass

                allocator.encode(asm.POP(asm.r9))
                allocator.encode(asm.POP(asm.r8))

                # Make the sub and push the results
                allocator.encode(asm.ADD(asm.r8, asm.r9))
                allocator.encode(asm.PUSH(asm.r8))
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_SUBTRACT):
                pass

                # Pop two values inside registers
                allocator.encode(asm.POP(asm.r9))
                allocator.encode(asm.POP(asm.r8))

                # Make the sub and push the results
                allocator.encode(asm.SUB(asm.r8, asm.r9))
                allocator.encode(asm.PUSH(asm.r8))

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

                # Pop the current TOS (the value)
                allocator.encode(asm.POP(asm.rax))

                # Now we need to clean the stack by modifying rsp
                allocator.encode(asm.MOV(asm.registers.rsp, asm.rbp))

                # Restore RBP for the caller
                allocator.encode(asm.POP(asm.rbp))

                # Saving return address in a register
                allocator.encode(asm.POP(asm.rbx))

                # Clean the stack an remove parameters on this call
                for i in range(0, instruction.block.function.argcount+1):
                    allocator.encode(asm.POP(asm.r10))

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
                pass

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
                pass

                # We need to perform an allocation here
                value = block.function.consts[instruction.arguments]
                block.function.allocator.allocate_const(instruction, value)

            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_NAME):

                name = instruction.function.names[instruction.arguments]

                # We are loading something from builtins
                if name in stub_handler.primitive_addresses:
                    function_addr = stub_handler.primitive_addresses[name]

                    allocator.encode(asm.MOV(asm.r9, function_addr))
                    allocator.encode(asm.PUSH(asm.r9))
                    allocator.primitive_loaded = True
                else:
                    # Load a name in the local environment
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
                pass

                # Load the value and put it onto the stack
                allocator.encode(asm.PUSH(allocator.get_local_variable(instruction.arguments)))

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

                # Special case for a call to a primitive function
                if allocator.primitive_loaded:
                    # Set the parameter for C
                    allocator.encode(asm.MOV(asm.rdi, asm.operand.MemoryOperand(asm.registers.rsp - 32)))

                    #allocator.primitive_loaded = False

                # The return instruction will clean the stack
                allocator.encode(asm.CALL(asm.r9))

                # The return value is in rax, push it back on the stack
                allocator.encode(asm.PUSH(asm.rax))

            elif isinstance(instruction, interpreter.simple_interpreter.MAKE_FUNCTION):
                pass

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

                # TODO : temporary
                address = stub_handler.lib.get_address(stub_handler.ffi.from_buffer(allocator.code_section), allocator.code_offset + 22)

                stub_address = allocator.compile_function_stub(self.stub_handler, nbargs, address)
                allocator.encode(asm.MOV(asm.r10, stub_address))
                allocator.encode(asm.CALL(asm.r10))

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

            old_stub_offset = mfunction.allocator.stub_offset
            old_code_offset = mfunction.allocator.code_offset

            # Compile a stub for each branch
            mfunction.allocator.compile_stub(self.stub_handler, mfunction, id(jump_block))

            # And update the dictionary of ids and blocks
            address_false = mfunction.allocator.compile_stub(self.stub_handler, mfunction, id(notjump_block))

            # Compute the offset to the stub, by adding the size of the JL instruction
            offset = old_stub_offset - old_code_offset
            peachpy_instruction = asm.JL(asm.operand.RIPRelativeOffset(offset - 6))

            mfunction.allocator.encode(peachpy_instruction)

            jump_stub = stub_handler.Stub(jump_block, peachpy_instruction, old_code_offset)
            self.stub_dictionary[id(jump_block)] = jump_stub

            # For now, jump to the newly compiled stub,
            # This code will be patched later
            old_code_offset = mfunction.allocator.code_offset
            peachpy_instruction = asm.MOV(asm.r10, address_false)
            mfunction.allocator.encode(peachpy_instruction)
            mfunction.allocator.encode(asm.JMP(asm.r10))

            # We store the MOV into the register as the jumping instruction, we just need to patch this
            notjump_stub = stub_handler.Stub(notjump_block, peachpy_instruction, old_code_offset)
            self.stub_dictionary[id(notjump_block)] = notjump_stub
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

            old_stub_offset = mfunction.allocator.stub_offset
            old_code_offset = mfunction.allocator.code_offset


            # Compile a stub for each branch
            mfunction.allocator.compile_stub(self.stub_handler, mfunction, id(jump_block))

            # And update the dictionary of ids and blocks
            address_false = mfunction.allocator.compile_stub(self.stub_handler, mfunction, id(notjump_block))

            # Compute the offset to the stub, by adding the size of the JG instruction
            offset = old_stub_offset - old_code_offset
            peachpy_instruction = asm.JG(asm.operand.RIPRelativeOffset(offset-6))

            mfunction.allocator.encode(peachpy_instruction)

            jump_stub = stub_handler.Stub(jump_block, peachpy_instruction, old_code_offset)
            self.stub_dictionary[id(jump_block)] = jump_stub

            # For now, jump to the newly compiled stub,
            # This code will be patched later
            old_code_offset = mfunction.allocator.code_offset
            peachpy_instruction = asm.MOV(asm.r10, address_false)
            mfunction.allocator.encode(peachpy_instruction)
            mfunction.allocator.encode(asm.JMP(asm.r10))

            # We store the MOV into the register as the jumping instruction, we just need to patch this
            notjump_stub = stub_handler.Stub(notjump_block, peachpy_instruction, old_code_offset)
            self.stub_dictionary[id(notjump_block)] = notjump_stub
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
    def __init__(self, mfunction, jitcompiler):
        self.function = mfunction
        self.jitcompiler = jitcompiler

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
        self.stub_offset = 400

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

        # A primitive function has been loaded, the call will follow
        # TODO: find something better
        self.primitive_loaded = False

        # Compile a prolog only for the main function, other functions don't need that
        if self.function.name == "main":
            self.compile_prolog([0])

    # Compile the loading of arguments of the function
    def arguments_loading(self):

        # FIXME: for now all parameters are 64 bits integers

        # Mapping between variables names and memory
        self.function.allocations = {}

        # Constructing a new stack frame by saving rbp
        self.encode(asm.PUSH(asm.rbp))
        self.encode(asm.MOV(asm.rbp, asm.registers.rsp))

    # Allocate a value and update the environment, this function create an instruction to store the value
    # instruction : The instruction
    # value : the value to allocate
    def allocate_const(self, instruction, value):
        if isinstance(value, int):
            # Put the integer value on the stack
            self.encode(asm.PUSH(value))
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

        # Store each byte in memory and update code_offset
        self.code_offset = self.write_instruction(encoded, self.code_offset)

    # Compile a stub in a special area of the code section
    # mstub_handler : StubHandler instance
    # mfunction : current function
    # id_block : id to put in the stub
    def compile_stub(self, mstub_handler, mfunction, id_block):
        return mstub_handler.compile_stub(mfunction, id_block)

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
        # TODO: Adapt types to the correct ones
        # result_type = None if function.result_type is None else function.result_type.as_ctypes_type
        # argument_types = [arg.c_type.as_ctypes_type for arg in function.arguments]

        self.function_type = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64)
        self.function_pointer = self.function_type(self.code_address)

    # Get the local variable from the number in parameter
    def get_local_variable(self, argument):
        varname = self.function.varnames[argument]

        # TODO: correct computation of parameter address
        offset = 16 * (argument+1)
        self.encode(asm.MOV(asm.r9, asm.operand.MemoryOperand(asm.registers.rbp + offset)))

        return asm.r9

    # Call the compiled function
    def __call__(self, *args):

        # #print the asm code
        if self.jitcompiler.interpreter.args.asm:
            self.disassemble_asm()

        # Make the actual call
        return self.function_pointer(*args)

    # Compile a fraction of code to call the correct function with its parameters
    def compile_prolog(self, args):

        # Save rbp
        self.encode(asm.PUSH(asm.rbp))
        self.encode(asm.MOV(asm.rbp, asm.registers.rsp))

        # Call the function just after this prolog
        # Minus the size of the return and stack's cleaning
        offset = self.code_offset
        self.encode(asm.CALL(asm.operand.RIPRelativeOffset(offset+1)))

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

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for i in md.disasm(bytes(self.code_section), self.code_address):
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        print("\n")

    # Compiled a call to a C function which print the stack from the stack frame
    def print_stack(self):

        self.encode(asm.MOV(asm.rdi, asm.registers.rbp))
        reg_id = asm.r10

        function_address = int(
            stub_handler.ffi.cast("intptr_t", stub_handler.ffi.addressof(stub_handler.lib, "print_stack")))
        self.encode(asm.MOV(reg_id, function_address))
        self.encode(asm.CALL(reg_id))

    # Compiled a call to a C function which print the data section
    def print_data_section(self):
        # Save rbp
        self.encode(asm.PUSH(asm.rbp))

        self.encode(asm.MOV(asm.rdi, self.data_address))
        self.encode(asm.MOV(asm.rsi, 50))

        reg_id = asm.r10

        function_address = int(
            stub_handler.ffi.cast("intptr_t", stub_handler.ffi.addressof(stub_handler.lib, "print_data_section")))
        self.encode(asm.MOV(reg_id, function_address))
        self.encode(asm.CALL(reg_id))

        # Restore rbp from the stack
        self.encode(asm.POP(asm.rbp))
