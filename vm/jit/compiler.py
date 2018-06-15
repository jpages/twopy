'''
This module contains the JIT compiler
'''

import sys
import ctypes

# rename for better code visibility
import peachpy.x86_64 as asm

import frontend
from . import stub_handler
from . import objects
from . import allocator
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
        self.tags = objects.TagHandler(self)

        # Allocate code and data sections
        self.global_allocator = allocator.GlobalAllocator(self)

        # The dynamic memory allocator (will be initialized during the compilation of main function)
        self.runtime_allocator = None

        # Collection of function which are classes
        self.class_functions = list()
        self.class_names = list()

        # Default value for max versions of versioning
        self.maxvers = 5

        if self.interpreter.args.maxvers:
            self.maxvers = self.interpreter.args.maxvers

    # Main function called by the launcher
    def execute(self):
        self.start()

    # Start the execution
    def start(self):
        # Start by compiling standard library
        self.compile_std_lib()

        # Generate the main function and recursively other functions in module
        mainfunc = self.interpreter.generate_function(self.maincode, "main", self.mainmodule, True)
        self.compile_function(mainfunc)

    # Compile the standard library
    def compile_std_lib(self):

        if self.interpreter.args.no_std_lib:
            return

        # Get the absolute path to the library file
        import os
        import sys
        absolute_path = os.path.abspath(os.path.dirname(sys.argv[0]))

        library_code = frontend.compiler.compile(absolute_path+"/jit/standard_library.py", self.interpreter.args)

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
            addr = int(stub_handler.ffi.cast("intptr_t", stub_handler.ffi.addressof(stub_handler.lib, "twopy_print")))
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

    # Compile the function  in parameter to binary code
    # return the code instance
    def compile_function(self, mfunction):
        if mfunction.allocator and mfunction.allocator is not None:
            return
        else:

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

            # Special case for primitive functions
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
        context = allocator.versioning.current_version().get_context_for_block(block)
        self.current_block = block

        # Offset of the first instruction compiled in the block
        return_offset = 0

        # If we are compiling the first block of the function, compile the prolog
        if block == mfunction.start_basic_block and index == 0:
            # TODO: use the compile_prolog function in allocator to do this
            self.compile_prolog(mfunction)

            if mfunction.is_class:
                # Store its name
                self.class_names.append(mfunction.name)

        for i in range(index, len(block.instructions)):
            # If its the first instruction of the block, save its offset
            if i == 0:
                return_offset = self.global_allocator.code_offset

            instruction = block.instructions[i]
            # big dispatch for all instructions
            if isinstance(instruction, interpreter.simple_interpreter.POP_TOP):

                context.pop_value()
                # Just discard the TOS value
                allocator.encode(asm.POP(asm.r10))
            elif isinstance(instruction, interpreter.simple_interpreter.ROT_TWO):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.ROT_THREE):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.DUP_TOP):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.DUP_TOP_TWO):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.NOP):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.UNARY_POSITIVE):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.UNARY_NEGATIVE):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.UNARY_NOT):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.UNARY_INVERT):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_MATRIX_MULTIPLY):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_MATRIX_MULTIPLY):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_POWER):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_MULTIPLY):

                self.tags.binary_operation("mul", mfunction, block, i+1)

            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_MODULO):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_ADD):

                #TODO: ensure that this operator wasn't redefined
                self.tags.binary_operation("add", mfunction, block, i+1)

            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_SUBTRACT):

                #TODO: ensure that this operator wasn't redefined
                self.tags.binary_operation("sub", mfunction, block, i+1)

            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_SUBSCR):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_FLOOR_DIVIDE):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_TRUE_DIVIDE):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_FLOOR_DIVIDE):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_TRUE_DIVIDE):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.GET_AITER):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.GET_ANEXT):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BEFORE_ASYNC_WITH):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_ADD):

                allocator.encode(asm.POP(asm.r9))

                # Perform the operation on the stack
                allocator.encode(asm.ADD(asm.operand.MemoryOperand(asm.registers.rsp), asm.r9))

            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_SUBTRACT):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_MULTIPLY):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_MODULO):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_SUBSCR):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_SUBSCR):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_LSHIFT):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_RSHIFT):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_AND):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_XOR):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BINARY_OR):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_POWER):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.GET_ITER):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.GET_YIELD_FROM_ITER):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.PRINT_EXPR):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_BUILD_CLASS):
                self.stub_handler.compile_class_stub(mfunction)

                # Get the following class name which should be a LOAD_CONST instruction
                const_number = block.instructions[i + 2].arguments
                name = block.function.consts[const_number]
                self.class_names.append(name)
            elif isinstance(instruction, interpreter.simple_interpreter.YIELD_FROM):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.GET_AWAITABLE):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_LSHIFT):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_RSHIFT):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_AND):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_XOR):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.INPLACE_OR):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BREAK_LOOP):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.WITH_CLEANUP_START):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.WITH_CLEANUP_FINISH):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.RETURN_VALUE):

                # Pop the current TOS (the value)
                allocator.encode(asm.POP(asm.rax))

                # Remove local variables from the stack
                if instruction.block.function.nb_pure_locals != 0:
                    allocator.encode(asm.ADD(asm.registers.rsp, (8*instruction.block.function.nb_pure_locals)))

                # Saving return address in a register
                allocator.encode(asm.POP(asm.rbx))

                # Keep the stack size correct
                for i in range(0, instruction.block.function.argcount + 1 + instruction.block.function.nb_pure_locals):
                    allocator.versioning.current_version().get_context_for_block(block).increase_stack_size()

                # Remove arguments and locals from the stack
                to_depop = 8*(instruction.block.function.argcount + 1)

                allocator.encode(asm.ADD(asm.registers.rsp, to_depop))

                # Finally returning by jumping
                allocator.encode(asm.JMP(asm.rbx))

            elif isinstance(instruction, interpreter.simple_interpreter.IMPORT_STAR):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_ANNOTATIONS):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.YIELD_VALUE):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.POP_BLOCK):
                # We don't need to implement this for loops
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.END_FINALLY):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.POP_EXCEPT):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.HAVE_ARGUMENT):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_NAME):
                # If we are compiling a class, store the value inside the class and not in the global environment
                if mfunction.is_class:
                    # Get the class address in a register
                    register = allocator.get_class_address(block)

                    # Update the model of the class
                    mfunction.mclass.vtable.append(mfunction.names[instruction.arguments])

                    # The position is the last added item to the vtable (*64 bits to get the correct position)
                    offset = len(mfunction.mclass.vtable) * 8

                    # Now store the value inside the class at the appropriate position
                    # First, remove the tag and get the address of the class
                    allocator.encode(asm.SHR(register, 2))

                    # Store TOS in rbx
                    allocator.encode(asm.POP(asm.rbx))

                    # Finally store the value in the class space
                    allocator.encode(asm.MOV(asm.operand.MemoryOperand(register + offset), asm.rbx))
                else:
                    # Store a name in the local environment
                    allocator.encode(asm.MOV(asm.r9, allocator.data_address))

                    # Write TOS at the instruction.arguments index in data_section
                    allocator.encode(asm.POP(asm.r10))

                    # Offset of the instruction's argument + r9 value
                    memory_address = asm.r9 + (64*instruction.arguments)
                    allocator.encode(asm.MOV(asm.operand.MemoryOperand(memory_address), asm.r10))

            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_NAME):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.UNPACK_SEQUENCE):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.FOR_ITER):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.UNPACK_EX):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_ATTR):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_ATTR):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_GLOBAL):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_GLOBAL):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_CONST):
                # We need to perform an allocation here
                value = block.function.consts[instruction.arguments]
                block.function.allocator.allocate_const(instruction, value, context)

            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_NAME):
                name = instruction.function.names[instruction.arguments]

                context.push_value(name, objects.Types.Unknown)

                # Determine what we need to load
                # LOAD_NAME for a class can be followed by two categories of opcodes:
                # - LOAD_ATTR or STORE_ATTR
                # - CALL_FUNCTION
                # In the first case, we must load the class structure
                # In the second case, we have to load the __init__ method
                if name in self.class_names:
                    if isinstance(block.instructions[i + 1], interpreter.simple_interpreter.LOAD_ATTR) or \
                            isinstance(block.instructions[i + 1], interpreter.simple_interpreter.STORE_ATTR):
                        allocator.encode(asm.MOV(asm.r9, allocator.data_address))

                        # Offset of the instruction's argument + r9 value
                        memory_address = asm.r9 + (64 * instruction.arguments)
                        allocator.encode(asm.MOV(asm.r10, asm.operand.MemoryOperand(memory_address)))

                        allocator.encode(asm.PUSH(asm.r10))
                    else:
                        # Construct the instance
                        # Locate the init method for the class
                        pass

                # We are loading something from builtins
                elif name in stub_handler.primitive_addresses:
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
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_LIST):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_SET):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_MAP):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_ATTR):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.COMPARE_OP):

                # If this is the first time we seen this instruction, put a type-test here and return
                if index != block.instructions.index(instruction):
                    self.tags.binary_operation(self.compare_operators[instruction.arguments], mfunction, block, i)
                    return return_offset
                # Otherwise compile the instruction, the test was executed

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
                return return_offset
            elif isinstance(instruction, interpreter.simple_interpreter.IMPORT_NAME):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.IMPORT_FROM):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.JUMP_FORWARD):
                # Locate the target of the jump
                target_block = None
                for b in block.next:
                    # In case of empty blocks (this should not happened...)
                    if len(b.instructions) == 0:
                        continue

                    if b.instructions[0].offset == instruction.absolute_target:
                        target_block = b

                self.stub_handler.compile_absolute_jump(mfunction, target_block)

            elif isinstance(instruction, interpreter.simple_interpreter.JUMP_IF_FALSE_OR_POP):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.JUMP_IF_TRUE_OR_POP):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.JUMP_ABSOLUTE):
                # Locate the target of the jump
                target_block = None
                for b in instruction.block.next:
                    # In case of empty blocks (this should not happened...)
                    if len(b.instructions) == 0:
                        continue

                    if b.instructions[0].offset == instruction.arguments:
                        target_block = b

                self.stub_handler.compile_absolute_jump(mfunction, target_block)

            elif isinstance(instruction, interpreter.simple_interpreter.POP_JUMP_IF_FALSE):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.POP_JUMP_IF_TRUE):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_GLOBAL):

                name = mfunction.names[instruction.arguments]

                context.push_value(name)

                # Lookup in the global environment
                if name in self.interpreter.global_environment:
                    # Assume we have a regular function here for now
                    element = self.interpreter.global_environment[name]

                    allocator.encode(asm.MOV(asm.r9, self.dict_compiled_functions[element]))
                    allocator.encode(asm.PUSH(asm.r9))
                elif name in stub_handler.primitive_addresses:
                    function_address = stub_handler.primitive_addresses[name]

                    # Load the primitive function
                    allocator.encode(asm.MOV(asm.r9, function_address))
                    allocator.encode(asm.PUSH(asm.r9))
                else:
                    # Lookup in its module to find a name
                    element = mfunction.module.lookup(name, False)

                    allocator.encode(asm.MOV(asm.r9, self.dict_compiled_functions[element]))
                    allocator.encode(asm.PUSH(asm.r9))

            elif isinstance(instruction, interpreter.simple_interpreter.CONTINUE_LOOP):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_LOOP):
                # for now, we don't need to implement this instruction, the compilation will be made with jumps
                pass
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_EXCEPT):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_FINALLY):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_FAST):

                context.push_value(mfunction.varnames[instruction.arguments])

                # Load the value and put it onto the stack
                allocator.encode(asm.PUSH(allocator.get_local_variable(instruction.arguments, block)))

            elif isinstance(instruction, interpreter.simple_interpreter.STORE_FAST):
                allocator.encode(asm.POP(asm.r10))

                operand = context.memory_location(instruction.arguments, mfunction.varnames[instruction.arguments])
                allocator.encode(asm.MOV(operand, asm.r10))

                # Store the variable in the correct position on the stack
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_FAST):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_ANNOTATION):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.RAISE_VARARGS):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.CALL_FUNCTION):

                # Save the function address in r9
                allocator.encode(asm.MOV(asm.r9, asm.operand.MemoryOperand(asm.registers.rsp+8*instruction.arguments)))

                # The return instruction will clean the stack
                allocator.encode(asm.CALL(asm.r9))

                for y in range(0, instruction.block.function.argcount + 1):
                    allocator.versioning.current_version().get_context_for_block(block).decrease_stack_size()

                # The return value is in rax, push it back on the stack
                allocator.encode(asm.PUSH(asm.rax))

            elif isinstance(instruction, interpreter.simple_interpreter.MAKE_FUNCTION):

                # The name and the code object
                nbargs = 2

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
                address = stub_handler.lib.get_address(stub_handler.ffi.from_buffer(self.global_allocator.code_section), self.global_allocator.code_offset + 13)

                stub_address = self.stub_handler.compile_function_stub(mfunction, nbargs, address)

                allocator.encode(asm.MOV(asm.r10, stub_address))
                allocator.encode(asm.CALL(asm.r10))

                context.decrease_stack_size()

            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_SLICE):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_CLOSURE):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_DEREF):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.STORE_DEREF):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.DELETE_DEREF):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.CALL_FUNCTION_KW):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.CALL_FUNCTION_EX):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_WITH):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.EXTENDED_ARG):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.LIST_APPEND):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.SET_ADD):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.MAP_ADD):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.LOAD_CLASSDEREF):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_LIST_UNPACK):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_MAP_UNPACK):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_MAP_UNPACK_WITH_CALL):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_TUPLE_UNPACK):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_SET_UNPACK):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.SETUP_ASYNC_WITH):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.FORMAT_VALUE):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_CONST_KEY_MAP):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_STRING):
                self.nyi()
            elif isinstance(instruction, interpreter.simple_interpreter.BUILD_TUPLE_UNPACK_WITH_CALL):
                self.nyi()

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

        # first < second
        if instruction.arguments == 0:
            # Compile stubs for each branch
            self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JL)
        # first != second
        elif instruction.arguments == 3:
            self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JNE)
        # first > second
        elif instruction.arguments == 4:
            self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JG)
        else:
            self.nyi()

    #TODO: too much code duplication with the previous function
    # Functions used to compile a comparison then a jump after (a if)
    # mfunction : Current compiled function
    # instruction : Current python Bytecode instruction
    # next_instruction : The following instruction
    def compile_cmp_POP_JUMP_IF_TRUE(self, mfunction, instruction, next_instruction):
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
                    jump_block = block
                else:
                    # Continue the execution in the second block
                    notjump_block = block

            # Compile stubs for each branch
            self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JL)
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
                    jump_block = block
                else:
                    # Continue the execution in the second block
                    notjump_block = block

            # Compile stubs for each branch
            self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JG)
        else:
            self.nyi()

    def compile_cmp_beginning(self, mfunction):
        # Put both operand into registers
        second_register = asm.r8
        first_register = asm.r9
        mfunction.allocator.encode(asm.POP(second_register))
        mfunction.allocator.encode(asm.POP(first_register))
        mfunction.allocator.encode(asm.CMP(first_register, second_register))

    # Compile the prolog of a function, save some spaces for locals on the stack
    def compile_prolog(self, mfunction):
        # Compute the number of pure locals (not parameters)
        nb_locals = mfunction.nlocals - mfunction.argcount

        if nb_locals == 0:
            return

        for i in range(nb_locals):
            mfunction.allocator.versioning.current_version().get_context_for_block(mfunction.start_basic_block).increase_stack_size()

        # Save some space on the stack for locals
        mfunction.allocator.encode(asm.SUB(asm.registers.rsp, 8*nb_locals))

    # Throw an exception if something is not yet implemented
    def nyi(self):
        raise RuntimeError("NOT YET IMPLEMENTED")

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

        # Future code address
        self.code_address = jitcompiler.global_allocator.get_current_address()

        # Future data address
        self.data_address = jitcompiler.global_allocator.get_current_address()

        # If any, the size reserved for the prolog
        self.prolog_size = 0

        # Association between labels and addresses to print them
        self.jump_labels = dict()

        # Create a pointer to be able to call this function directly in python
        self.create_function_pointer()

        # Compile a prolog only for the main function, other functions don't need that
        if self.function.is_main:
            self.compile_prolog()

            # Initialize the Memory allocator
            self.jitcompiler.runtime_allocator = allocator.RuntimeAllocator(self.jitcompiler.global_allocator)
            self.jitcompiler.runtime_allocator.init_allocation_pointer()

    # Allocate a value and update the environment, this function create an instruction to store the value
    # instruction : The instruction
    # value : the value to allocate
    # context : current compilation context, has to be filled with the constant informations
    def allocate_const(self, instruction, value, context):

        # Bool are considered integers in python, we need to check this first
        if isinstance(value, bool):
            # Tag a boolean
            tvalue = self.jitcompiler.tags.tag_bool(value)
            self.encode(asm.PUSH(tvalue))
            context.push_value(value, objects.Types.Bool)
        elif isinstance(value, int):
            # Put the integer value on the stack
            tvalue = self.jitcompiler.tags.tag_integer(value)
            self.encode(asm.PUSH(tvalue))

            context.push_value(value, objects.Types.Int)
        elif isinstance(value, float):
            # TODO: Encode a float
            self.nyi()
        else:
            # For now assume it's consts
            const_object = self.function.consts[instruction.arguments]

            if isinstance(const_object, str):
                # Unicode encoding of the string
                encoded_value = const_object.encode()
                address = self.jitcompiler.global_allocator.allocate_object(encoded_value)

                # Put the tag
                tagged_address = self.jitcompiler.tags.tag_object(address)

                # Move this value in a register
                self.encode(asm.MOV(asm.r10, tagged_address))
                self.encode(asm.PUSH(asm.r10))

                self.jitcompiler.consts[tagged_address] = const_object

                context.push_value(const_object, objects.Types.String)
            else:
                self.encode(asm.MOV(asm.r10, id(const_object)))
                self.encode(asm.PUSH(asm.r10))

                self.jitcompiler.consts[id(const_object)] = const_object

                context.push_value(value, objects.Types.Unknown)

    # Create a pointer to the compiled function
    def create_function_pointer(self):
        self.function_type = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64)
        self.function_pointer = self.function_type(self.code_address)

    # Used to get the class address which is on the stack from the compilation context of a class-function
    # Return the register with the value inside
    # Below is a stack representation of a frame
    # -----------------------
    #   ...........
    #   old context
    # -----------------------
    #   class address
    # -----------------------
    #   return address
    # -----------------------
    #   locals
    # -----------------------
    #   parameters
    # -----------------------
    #   current stack pointer
    #
    def get_class_address(self, block):
        # Adding the stack size
        offset = self.versioning.current_version().get_context_for_block(block).stack_size * 8

        # And the number of arguments and locals
        offset += self.function.nlocals * 8

        # The return address
        offset += 8

        # Moving the result inside a register and return it
        self.encode(asm.MOV(asm.rax, asm.operand.MemoryOperand(asm.registers.rsp + offset)))

        return asm.rax


    # Get the local variable from the number in parameter and store it in a register
    # argument : number of the variable
    # block : enclosing block for this access
    def get_local_variable(self, argument, block):
        # If we try to load a pure local variable
        if argument > (self.function.argcount-1):
            # TODO: Factorize this code
            argument = argument - (self.function.argcount - 1)
            res = (8 * self.versioning.current_version().get_context_for_block(block).stack_size) - 8 * argument
            self.encode(asm.MOV(asm.r9, asm.operand.MemoryOperand(asm.registers.rsp + res)))
        else:
            offset = self.versioning.current_version().get_context_for_block(block).get_offset(argument)

            self.encode(asm.MOV(asm.r9, asm.operand.MemoryOperand(asm.registers.rsp + offset)))

        return asm.r9

    # Call the compiled function
    def __call__(self, *args):
        # Print the asm code
        if self.jitcompiler.interpreter.args.asm:
            self.jitcompiler.global_allocator.disassemble_asm()

        # Make the actual call
        return self.function_pointer(*args)

    # Compile a fraction of code to call the correct function with its parameters
    def compile_prolog(self):
        offset_before = self.jitcompiler.global_allocator.code_offset

        # Save rbp
        self.encode(asm.PUSH(asm.rbp))
        self.encode(asm.MOV(asm.rbp, asm.registers.rsp))

        # Call the function just after this prolog
        # Minus the size of the return and stack's cleaning

        instructions = []

        # Restore the stack
        instructions.append(asm.MOV(asm.registers.rsp, asm.rbp))
        instructions.append(asm.POP(asm.rbp))
        instructions.append(asm.RET())

        size = 0
        for i in instructions:
            size += len(i.encode())

        self.encode(asm.CALL(asm.operand.RIPRelativeOffset(size)))

        for i in instructions:
            self.encode(i)

        self.prolog_size = self.jitcompiler.global_allocator.code_offset - offset_before

    # TODO: to remove
    # Just a wrapper for migrate code to a global section
    def encode(self, instruction):
        self.jitcompiler.global_allocator.encode(instruction, self.function)

    # TODO: to remove
    # Just a wrapper for migrate code to a global section
    def encode_stub(self, instruction):
        return self.jitcompiler.global_allocator.encode_stub(instruction)

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
        version = Version(self)

        # Store the association
        first_context = Context(version, self.mfunction.start_basic_block)
        version.context_map[self.mfunction.start_basic_block] = first_context

        self.versions.append(version)

        self.generic_version = version

    # Return the version currently compiled
    def current_version(self):
        return self.generic_version


# A particular version
class Version:
    def __init__(self, versioning):
        self.versioning = versioning

        # Map between blocks and contexts
        self.context_map = {}

    # Create a context for a given block if needed
    # Return the newly created context or the preexistent one
    def get_context_for_block(self, block):
        if block in self.context_map:
            return self.context_map[block]
        else:
            context = Context(self, block)
            self.context_map[block] = context

            # Copy the previous stack size from a parent block
            for parent in block.previous:
                if parent in self.context_map:
                    # TODO: maybe do something if we have several compiled parent's blocks
                    context.stack_size = self.context_map[parent].stack_size

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


# Attached to a version and a block, contains informations such as stack size, types, etc.
class Context:
    # version : the associated version of the code
    # block : the associated block of this context
    def __init__(self, version, block):
        self.version = version
        self.block = block

        self.stack_size = 0

        # Dictionary between variables and their types
        self.variable_types = {}

        # Dictionary between variables and their registers
        self.variables_allocation = {}

        # TODO: initialize the stacks from the parent block
        # Virtual stack, association between positions on the stack and variables types
        self.stack = []

        # Initialize the virtual stack
        self.initialize_stack()

    def increase_stack_size(self):
        self.stack_size += 1

    def decrease_stack_size(self):
        self.stack_size -= 1

    # Get the offset from the rsp for the local variable number nbvariable
    def get_offset(self, nbvariable):
        res = (8 * self.stack_size) + 8*(self.version.versioning.mfunction.argcount - nbvariable)

        return res

    # Return the memory location of a given variable as a PeachPy operand
    # nb_variable : number of the variable in the function
    # name : its name
    def memory_location(self, nb_variable, name):
        # if we try to access a local which is not a parameter
        if nb_variable > (self.version.versioning.mfunction.argcount-1):

            nb_variable = nb_variable - (self.version.versioning.mfunction.argcount - 1)
            res = (8 * self.stack_size) - 8 * nb_variable
            return asm.operand.MemoryOperand(asm.registers.rsp + res)
        else:
            return asm.operand.MemoryOperand(asm.registers.rsp + self.get_offset(nb_variable))

    # Initialize the virtual stack which represents types on the stack
    def initialize_stack(self):
        # If this is the first block, without previous block
        if self.block:
            self.stack = []

        # TODO: if we have inter-procedural propagation, initialize the current context with values from the caller

    # TODO: Try to know if a value is duplicated on the stack, in this case store the information
    # Push a value onto the virtual stack
    def push_value(self, value, type_info=objects.Types.Unknown):

        # Make a tuple of a value and its type
        el = (value, type_info)
        self.stack.append(el)

        # If we add an unknown value on the stack, try to get its type
        for element in self.stack:
            if value == element[0] and type_info == objects.Types.Unknown:
                pass
                #print("Duplicated unknown value on the virtual stack : " + str(value))

    # Pop a value from the virtual stack
    def pop_value(self):
        self.stack.pop()

    # Set a value for a tuple in the virtual stack
    # Try to find duplicate in the stack and set them too
    def set_value(self, tuple, type_value):
        #TODO: find a better solution than this
        variable = tuple[0]

        for i in range(len(self.stack)):
            if self.stack[i][0] == variable:
                self.stack[i] = (variable, type_value)
