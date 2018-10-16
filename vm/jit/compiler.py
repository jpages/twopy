'''
This module contains the JIT compiler core
'''

import sys
import ctypes
from types import *
import struct

# rename for better code visibility
import peachpy.x86_64 as asm

import frontend
from frontend import model
from . import stub_handler
from . import objects
from . import allocator


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

        # Used to collect statistics
        self.register_stats = asm.rbx

        # Association between name of a class and the address of its initializer (allocation + init)
        self.initializer_addresses = dict()

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

        self.post_execution()

    # Initialize a register reserved to collect statistics on execution
    def init_statistics(self):
        if self.interpreter.args.stats:
            # Count the number of type-checks
            encoded = asm.MOV(self.register_stats, 0).encode()
            self.global_allocator.code_offset = self.global_allocator.write_instruction(encoded,
                                                                                    self.global_allocator.code_offset)

    # Called after the end of execution
    def post_execution(self):
        if self.interpreter.args.asm:
            self.global_allocator.disassemble_asm()

    # Compile the standard library
    def compile_std_lib(self):

        if self.interpreter.args.no_std_lib:
            return

        # Get the absolute path to the library file
        import os
        import sys
        absolute_path = os.path.abspath(os.path.dirname(sys.argv[0]))

        library_code = frontend.compiler.compile_source(absolute_path+"/jit/standard_library.py", self.interpreter.args)

        # Force the compilation of std functions
        stdlib_function = self.interpreter.generate_function(library_code, "std_lib", self.mainmodule, True)
        self.compile_function(stdlib_function)

    # Compile a standard function
    def compile_std_function(self, mfunction):

        # For now we just have the print here
        if mfunction.name == "twopy_print":
            # Make a call to C for the print

            # Move the parameter inside rdi to respect the calling convention
            mfunction.allocator.encode(asm.MOV(asm.rdi, asm.operand.MemoryOperand(asm.registers.rsp + 8)))

            # Move the C-print address inside r9
            addr = int(stub_handler.ffi.cast("intptr_t", stub_handler.ffi.addressof(stub_handler.lib, "twopy_print")))
            mfunction.allocator.encode(asm.MOV(asm.r9, addr))

            # The return instruction will clean the stack
            mfunction.allocator.encode(asm.CALL(asm.r9))

            # The return value is in rax

            # Saving return address in a register
            mfunction.allocator.encode(asm.POP(asm.r10))

            for k in range(0, mfunction.argcount + 1 + mfunction.nb_pure_locals):
                mfunction.allocator.versioning.current_version().get_context_for_block(mfunction.start_basic_block).increase_stack_size()

            # Remove print parameters
            mfunction.allocator.encode(asm.ADD(asm.registers.rsp, 8*(mfunction.argcount+1)))

            # Finally returning by jumping
            mfunction.allocator.encode(asm.JMP(asm.r10))

            stub_handler.primitive_addresses["print"] = mfunction.allocator.code_address
        else:
            # Storing the real name of the primitive instead of the twopy name
            short_name = mfunction.name.replace("twopy_", "")
            stub_handler.primitive_addresses[short_name] = mfunction.allocator.code_address

            # Force the compilation of these functions
            self.compile_instructions(mfunction, mfunction.start_basic_block)

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
            if "standard_library.py" in mfunction.filename:
                self.compile_std_function(mfunction)
            else:
                # Start the compilation of the first basic block
                self.compile_instructions(mfunction, mfunction.start_basic_block)

            # Associate this function with its address
            self.dict_compiled_functions[mfunction] = allocator.code_address + allocator.prolog_size

            if mfunction.name == "main" or mfunction.name == "std_lib":
                # Call the main with a random value
                str(allocator(42))

    # Compile all instructions of a basic block to binary code
    # mfunction : the simple_interpreter.Function object
    # block : The BasicBlock to compile
    # index : Start the compilation from an index in the block, default 0
    def compile_instructions(self, mfunction, block, index=0):

        allocator = mfunction.allocator

        # Do not compile an already compiled block
        if block.compiled:
            return block.first_offset

        # Force the creation of a context
        context = allocator.versioning.current_version().get_context_for_block(block)
        self.current_block = block

        # Offset of the first instruction compiled in the block
        return_offset = 0

        # print("Compiling the block " + str(id(block)))
        # for ins in block.instructions:
        #     print("\t" + str(ins))

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
            if isinstance(instruction, model.POP_TOP):

                context.pop_value()
                context.decrease_stack_size()

                # Just discard the TOS value
                allocator.encode(asm.ADD(asm.registers.rsp, 8))
            elif isinstance(instruction, model.ROT_TWO):
                self.nyi()
            elif isinstance(instruction, model.ROT_THREE):
                self.nyi()
            elif isinstance(instruction, model.DUP_TOP):
                self.nyi()
            elif isinstance(instruction, model.DUP_TOP_TWO):
                self.nyi()
            elif isinstance(instruction, model.NOP):
                self.nyi()
            elif isinstance(instruction, model.UNARY_POSITIVE):
                self.nyi()
            elif isinstance(instruction, model.UNARY_NEGATIVE):
                self.nyi()
            elif isinstance(instruction, model.UNARY_NOT):
                self.nyi()
            elif isinstance(instruction, model.UNARY_INVERT):
                self.nyi()
            elif isinstance(instruction, model.BINARY_MATRIX_MULTIPLY):
                self.nyi()
            elif isinstance(instruction, model.INPLACE_MATRIX_MULTIPLY):
                self.nyi()
            elif isinstance(instruction, model.BINARY_POWER):
                self.nyi()
            elif isinstance(instruction, model.BINARY_MULTIPLY):
                reg0 = asm.r13
                reg1 = asm.r14
                instructions = []
                instructions.append(asm.POP(reg1))
                instructions.append(asm.POP(reg0))

                instructions.append(self.tags.untag_asm(reg0))
                instructions.append(asm.IMUL(reg0, reg1))

                # We need the size of these instructions when encoded
                encoded = []
                for ins in instructions:
                    encoded.append(ins.encode())
                    allocator.encode(ins)

                # Get current instruction offset
                current_offset = stub_handler.lib.get_address(
                    stub_handler.ffi.from_buffer(self.global_allocator.code_section),
                    self.global_allocator.code_offset)

                # Adding the length of previous instructions in the list and the size of the JO
                current_offset += len(encoded) + 14

                # Jump to an error handler if overflow
                address_error = stub_handler.stubhandler_instance.compile_error_stub(1)
                diff = address_error - current_offset

                # For now, jump to a stub which will print an error and exit
                # This need to be replaced with a proper overflow handling and a conversion to bignums
                allocator.encode(asm.JO(asm.operand.RIPRelativeOffset(diff)))
                allocator.encode(asm.PUSH(reg0))

                # Update the stack
                context.pop_value()
                context.pop_value()

                context.push_value("", objects.Types.Int)

            elif isinstance(instruction, model.BINARY_MODULO):
                self.nyi()
            elif isinstance(instruction, model.BINARY_ADD):

                # Get the two elements, we should know their types by now
                first_element = context.pop_value()
                second_element = context.pop_value()

                first_type = first_element[1]
                second_type = second_element[1]

                # Registers to perform the operation
                reg0 = None
                reg1 = None

                # Instructions in tests
                instructions = []

                # Encoded version to compute the size for the overflow test
                encoded = []

                # We need to unbox values
                if first_type == objects.Types.Float and second_type == objects.Types.Float:
                    reg0 = asm.r13
                    reg1 = asm.r14

                    # Get the two boxed values and unbox them
                    instructions.append(asm.POP(reg0))
                    instructions.append(self.tags.untag_asm(asm.r13))

                    instructions.append(asm.POP(reg1))
                    instructions.append(self.tags.untag_asm(asm.r14))

                    # Move into XMM registers the unboxed values
                    instructions.append(asm.MOVQ(asm.xmm0, asm.operand.MemoryOperand(reg0+8)))
                    instructions.append(asm.MOVQ(asm.xmm1, asm.operand.MemoryOperand(reg1+8)))

                    # Make the addition
                    instructions.append(asm.ADDSD(asm.xmm0, asm.xmm1))

                    # Allocate the space for the result of the addition
                    result_register = self.runtime_allocator.allocate_object_with_size(instructions, 2, reg0)
                    instructions.append(asm.MOVQ(asm.operand.MemoryOperand(result_register+8), asm.xmm0))

                    instructions.extend(self.tags.tag_float_asm(result_register))

                    context.push_value("", objects.Types.Float)
                else:
                    # Integers
                    reg0 = asm.r13
                    reg1 = asm.r14

                    instructions.append(asm.POP(reg1))
                    instructions.append(asm.POP(reg0))
                    instructions.append(asm.ADD(reg0, reg1))

                    context.push_value("", objects.Types.Int)

                # We need the size of these instructions when encoded
                for ins in instructions:
                    encoded.append(ins.encode())
                    allocator.encode(ins)

                # Get current instruction offset
                current_offset = stub_handler.lib.get_address(
                    stub_handler.ffi.from_buffer(self.global_allocator.code_section),
                    self.global_allocator.code_offset)

                # Adding the length of previous instructions in the list and the size of the JO
                current_offset += len(encoded) + 14

                # Jump to an error handler if overflow
                address_error = stub_handler.stubhandler_instance.compile_error_stub(1)
                diff = address_error - current_offset

                # For now, jump to a stub which will print an error and exit
                # This need to be replaced with a proper overflow handling and a conversion to bignums
                allocator.encode(asm.JO(asm.operand.RIPRelativeOffset(diff)))
                allocator.encode(asm.PUSH(reg0))
            elif isinstance(instruction, model.BINARY_SUBTRACT):
                # Get the two elements, we should know their types by now
                first_element = context.pop_value()
                second_element = context.pop_value()

                first_type = first_element[1]
                second_type = second_element[1]

                # Registers to perform the operation
                reg0 = None
                reg1 = None

                # Instructions in tests
                instructions = []

                # Encoded version to compute the size for the overflow test
                encoded = []

                # We need to unbox values
                if first_type == objects.Types.Float and second_type == objects.Types.Float:
                    reg0 = asm.r13
                    reg1 = asm.r14

                    # Get the two boxed values and unbox them
                    instructions.append(asm.POP(reg1))
                    instructions.append(self.tags.untag_asm(asm.r14))

                    instructions.append(asm.POP(reg0))
                    instructions.append(self.tags.untag_asm(asm.r13))

                    # Move into XMM registers the unboxed values
                    instructions.append(asm.MOVQ(asm.xmm0, asm.operand.MemoryOperand(reg0+8)))
                    instructions.append(asm.MOVQ(asm.xmm1, asm.operand.MemoryOperand(reg1+8)))

                    # Make the addition and move the result to one of the operand
                    instructions.append(asm.SUBSD(asm.xmm0, asm.xmm1))

                    result_register = self.runtime_allocator.allocate_object_with_size(instructions, 2, reg0)
                    instructions.append(asm.MOVQ(asm.operand.MemoryOperand(result_register + 8), asm.xmm0))

                    instructions.extend(self.tags.tag_float_asm(result_register))

                    context.push_value("", objects.Types.Float)
                else:
                    # Integers
                    reg0 = asm.r13
                    reg1 = asm.r14

                    instructions.append(asm.POP(reg1))
                    instructions.append(asm.POP(reg0))
                    instructions.append(asm.SUB(reg0, reg1))

                    context.push_value("", objects.Types.Int)

                # We need the size of these instructions when encoded
                for ins in instructions:
                    encoded.append(ins.encode())
                    allocator.encode(ins)

                # Get current instruction offset
                current_offset = stub_handler.lib.get_address(
                    stub_handler.ffi.from_buffer(self.global_allocator.code_section),
                    self.global_allocator.code_offset)

                # Adding the length of previous instructions in the list and the size of the JO
                current_offset += len(encoded) + 14

                # Jump to an error handler if overflow
                address_error = stub_handler.stubhandler_instance.compile_error_stub(1)
                diff = address_error - current_offset

                # For now, jump to a stub which will print an error and exit
                # This need to be replaced with a proper overflow handling and a conversion to bignums
                allocator.encode(asm.JO(asm.operand.RIPRelativeOffset(diff)))
                allocator.encode(asm.PUSH(reg0))
            elif isinstance(instruction, model.BINARY_SUBSCR):
                self.nyi()
            elif isinstance(instruction, model.BINARY_FLOOR_DIVIDE):
                self.nyi()
            elif isinstance(instruction, model.BINARY_TRUE_DIVIDE):
                self.nyi()
            elif isinstance(instruction, model.INPLACE_FLOOR_DIVIDE):
                self.nyi()
            elif isinstance(instruction, model.INPLACE_TRUE_DIVIDE):
                self.nyi()
            elif isinstance(instruction, model.GET_AITER):
                self.nyi()
            elif isinstance(instruction, model.GET_ANEXT):
                self.nyi()
            elif isinstance(instruction, model.BEFORE_ASYNC_WITH):
                self.nyi()
            elif isinstance(instruction, model.INPLACE_ADD):

                allocator.encode(asm.POP(asm.r9))

                # Perform the operation on the stack
                allocator.encode(asm.ADD(asm.operand.MemoryOperand(asm.registers.rsp), asm.r9))

                context.pop_value()
            elif isinstance(instruction, model.INPLACE_SUBTRACT):
                self.nyi()
            elif isinstance(instruction, model.INPLACE_MULTIPLY):
                self.nyi()
            elif isinstance(instruction, model.INPLACE_MODULO):
                self.nyi()
            elif isinstance(instruction, model.STORE_SUBSCR):
                self.nyi()
            elif isinstance(instruction, model.DELETE_SUBSCR):
                self.nyi()
            elif isinstance(instruction, model.BINARY_LSHIFT):
                self.nyi()
            elif isinstance(instruction, model.BINARY_RSHIFT):
                self.nyi()
            elif isinstance(instruction, model.BINARY_AND):
                self.nyi()
            elif isinstance(instruction, model.BINARY_XOR):
                self.nyi()
            elif isinstance(instruction, model.BINARY_OR):
                self.nyi()
            elif isinstance(instruction, model.INPLACE_POWER):
                self.nyi()
            elif isinstance(instruction, model.GET_ITER):
                # TOS = iter(TOS)
                # We need to call the method iter() on the top on stack
                # Copy the top of stack and leave on the stack the object
                allocator.encode(asm.MOV(asm.r10, asm.operand.MemoryOperand(asm.registers.rsp)))

                # Remove the tag
                untag_instruction = self.tags.untag_asm(asm.r10)
                allocator.encode(untag_instruction)

                # Get the class pointer
                allocator.encode(asm.MOV(asm.r11, asm.operand.MemoryOperand(asm.r10 + 8)))

                # Make the static call to the method __twopy__iter in this class
                iter_offset = primitive_offsets_methods["twopy_iter"]

                allocator.encode(asm.CALL(asm.operand.MemoryOperand(asm.r11 + (8 * iter_offset))))

                # Twopy_iter has 2 arguments plus the return address
                for y in range(3):
                    allocator.versioning.current_version().get_context_for_block(block).decrease_stack_size()

                # Push the iterator on the stack
                allocator.encode(asm.PUSH(asm.rax))
            elif isinstance(instruction, model.GET_YIELD_FROM_ITER):
                self.nyi()
            elif isinstance(instruction, model.PRINT_EXPR):
                self.nyi()
            elif isinstance(instruction, model.LOAD_BUILD_CLASS):
                self.stub_handler.compile_class_stub(mfunction)

                # Get the following class name which should be a LOAD_CONST instruction
                const_number = block.instructions[i + 2].argument
                name = block.function.consts[const_number]
                self.class_names.append(name)
            elif isinstance(instruction, model.YIELD_FROM):
                self.nyi()
            elif isinstance(instruction, model.GET_AWAITABLE):
                self.nyi()
            elif isinstance(instruction, model.INPLACE_LSHIFT):
                self.nyi()
            elif isinstance(instruction, model.INPLACE_RSHIFT):
                self.nyi()
            elif isinstance(instruction, model.INPLACE_AND):
                self.nyi()
            elif isinstance(instruction, model.INPLACE_XOR):
                self.nyi()
            elif isinstance(instruction, model.INPLACE_OR):
                self.nyi()
            elif isinstance(instruction, model.BREAK_LOOP):
                self.nyi()
            elif isinstance(instruction, model.WITH_CLEANUP_START):
                self.nyi()
            elif isinstance(instruction, model.WITH_CLEANUP_FINISH):
                self.nyi()
            elif isinstance(instruction, model.RETURN_VALUE):
                # Pop the current TOS (the value)
                allocator.encode(asm.POP(asm.rax))

                # Remove local variables from the stack
                if instruction.block.function.nb_pure_locals != 0:
                    allocator.encode(asm.ADD(asm.registers.rsp, (8*instruction.block.function.nb_pure_locals)))

                # Saving return address in a register
                allocator.encode(asm.POP(asm.r10))

                # Keep the stack size correct
                for k in range(0, instruction.block.function.argcount + 1 + instruction.block.function.nb_pure_locals):
                    context.increase_stack_size()

                # Remove arguments and locals from the stack
                to_depop = 8*(instruction.block.function.argcount + 1)

                if "__init__" in mfunction.name:
                    # Keep self to return it
                    to_depop -= 16

                allocator.encode(asm.ADD(asm.registers.rsp, to_depop))

                # We want to return the newly created object
                if "__init__" in mfunction.name:
                    allocator.encode(asm.POP(asm.rax))

                # Finally returning by jumping
                allocator.encode(asm.JMP(asm.r10))

            elif isinstance(instruction, model.IMPORT_STAR):
                self.nyi()
            elif isinstance(instruction, model.SETUP_ANNOTATIONS):
                self.nyi()
            elif isinstance(instruction, model.YIELD_VALUE):
                self.nyi()
            elif isinstance(instruction, model.POP_BLOCK):
                # We don't need to implement this for loops
                pass
            elif isinstance(instruction, model.END_FINALLY):
                self.nyi()
            elif isinstance(instruction, model.POP_EXCEPT):
                self.nyi()
            elif isinstance(instruction, model.HAVE_ARGUMENT):
                self.nyi()
            elif isinstance(instruction, model.STORE_NAME):
                # If we are compiling a class, store the value inside the class and not in the global environment
                if mfunction.is_class:
                    # Get the class address in a register
                    register = allocator.get_class_address(block)

                    # The position is the last added item to the vtable (*8 bytes to get the correct position)
                    offset = len(mfunction.mclass.vtable) * 8

                    # Update the model of the class
                    mfunction.mclass.vtable.append(mfunction.names[instruction.argument])

                    # Now store the value inside the class at the appropriate position
                    # First, remove the tag and get the address of the class
                    allocator.encode(asm.SHR(register, 3))

                    # Store TOS in r10
                    allocator.encode(asm.POP(asm.r10))

                    # Finally store the value in the class space
                    allocator.encode(asm.MOV(asm.operand.MemoryOperand(register + offset), asm.r10))

                    # Increment the class static allocator to no write on an already defined class later
                    self.global_allocator.class_offset += 8
                else:
                    name = mfunction.names[instruction.argument]

                    # Store a name in the local environment
                    allocator.encode(asm.MOV(asm.r9, allocator.data_address))

                    # Write TOS at the instruction.arguments index in data_section
                    allocator.encode(asm.POP(asm.r10))

                    # Offset of the instruction's argument + r9 value
                    memory_address = asm.r9 + (64 * instruction.argument)
                    allocator.encode(asm.MOV(asm.operand.MemoryOperand(memory_address), asm.r10))

                    if name in self.class_names:
                        # Keep track on primitive class addresses
                        stub_handler.primitive_addresses[name] = 64 * instruction.argument + allocator.data_address

            elif isinstance(instruction, model.DELETE_NAME):
                self.nyi()
            elif isinstance(instruction, model.UNPACK_SEQUENCE):
                self.nyi()
            elif isinstance(instruction, model.FOR_ITER):
                # Save the receiver into a register
                allocator.encode(asm.MOV(asm.r10, asm.operand.MemoryOperand(asm.registers.rsp)))

                # Save some space on the stack, we want to keep the iterator on the stack after the call
                # Duplicate the iterator, this one will be cleaned by the callee
                allocator.encode(asm.PUSH(asm.r10))
                allocator.encode(asm.PUSH(asm.r10))

                untag_instruction = self.tags.untag_asm(asm.r10)
                allocator.encode(untag_instruction)

                # Get the class pointer
                allocator.encode(asm.MOV(asm.r11, asm.operand.MemoryOperand(asm.r10 + 8)))

                # Make the static call to the method __twopy__iter in this class
                iter_offset = primitive_offsets_methods["twopy_next"]

                allocator.encode(asm.CALL(asm.operand.MemoryOperand(asm.r11 + (8 * iter_offset))))

                # 2 parameters and the return address for twopy_next()
                for y in range(3):
                    allocator.versioning.current_version().get_context_for_block(block).decrease_stack_size()

                # Push the value returned on the stack
                allocator.encode(asm.PUSH(asm.rax))

                # The next() method returns the boolean False if the iterator is exhausted (represented by 2)
                allocator.encode(asm.CMP(asm.rax, 2))

                true_block = None
                false_block = None

                for b in instruction.block.next:
                    if b.instructions[0].offset == instruction.absolute_target:
                        # Make the jump
                        true_block = b
                    else:
                        # Continue
                        false_block = b

                # Pop some values if we need to end the loop
                # Pop the returned value, the iterator and its last value on the stack
                true_instructions = [asm.ADD(asm.registers.rsp, 8)]

                # Now compare the value and make the jump to correct block
                self.stub_handler.compile_bb_stub(mfunction, true_block, false_block, asm.JE, true_instructions)

            elif isinstance(instruction, model.UNPACK_EX):
                self.nyi()
            elif isinstance(instruction, model.STORE_ATTR):

                name = mfunction.names[instruction.argument]

                # The object
                allocator.encode(asm.POP(asm.r10))

                # The value
                allocator.encode(asm.POP(asm.r11))

                # Untag the object
                allocator.encode(self.tags.untag_asm(asm.r10))

                # Test if we have a static offset for this attribute
                if name in primitive_offsets_attributes:
                    static_offset = primitive_offsets_attributes[name]
                    allocator.encode(asm.MOV(asm.operand.MemoryOperand(asm.r10 + 8*static_offset), asm.r11))
                else:
                    # TODO: general case for attribute
                    self.nyi()

            elif isinstance(instruction, model.DELETE_ATTR):
                self.nyi()
            elif isinstance(instruction, model.STORE_GLOBAL):
                self.nyi()
            elif isinstance(instruction, model.DELETE_GLOBAL):
                self.nyi()
            elif isinstance(instruction, model.LOAD_CONST):
                # We need to perform an allocation here
                value = block.function.consts[instruction.argument]
                block.function.allocator.allocate_const(instruction, value, context)

            elif isinstance(instruction, model.LOAD_NAME):
                name = instruction.function.names[instruction.argument]

                context.push_value(name, objects.Types.Unknown)

                if name == "__name__":
                    self.compile_load_special(mfunction, name)
                elif name in self.class_names:
                    # Determine what we need to load
                    # LOAD_NAME for a class can be followed by two categories of opcodes:
                    # - LOAD_ATTR or STORE_ATTR
                    # - CALL_FUNCTION
                    # In the first case, we must load the class structure
                    # In the second case, we have to load the __init__ method
                    self.compile_load_class(allocator, block, i, instruction)
                elif name in stub_handler.primitive_addresses:
                    # We are loading something from builtins
                    function_address = stub_handler.primitive_addresses[name]

                    allocator.encode(asm.MOV(asm.r9, function_address))
                    allocator.encode(asm.PUSH(asm.r9))
                else:
                    # Load a name (a variable) in the local environment
                    allocator.encode(asm.MOV(asm.r9, allocator.data_address))

                    # Offset of the instruction's argument + r9 value
                    memory_address = asm.r9 + (64 * instruction.argument)
                    allocator.encode(asm.MOV(asm.r10, asm.operand.MemoryOperand(memory_address)))

                    allocator.encode(asm.PUSH(asm.r10))

            elif isinstance(instruction, model.BUILD_TUPLE):
                self.nyi()
            elif isinstance(instruction, model.BUILD_LIST):
                self.nyi()
            elif isinstance(instruction, model.BUILD_SET):
                self.nyi()
            elif isinstance(instruction, model.BUILD_MAP):
                self.nyi()
            elif isinstance(instruction, model.LOAD_ATTR):
                name = mfunction.names[instruction.argument]
                if name in primitive_offsets_attributes:
                    allocator.encode(asm.POP(asm.r10))
                    allocator.encode(self.tags.untag_asm(asm.r10))

                    allocator.encode(asm.MOV(asm.r11, asm.operand.MemoryOperand(asm.r10 + 8 * primitive_offsets_attributes[name])))
                    allocator.encode(asm.PUSH(asm.r11))
                elif name in primitive_offsets_methods:
                    allocator.encode(asm.POP(asm.r10))
                    allocator.encode(self.tags.untag_asm(asm.r10))

                    # Read the class pointer
                    allocator.encode(asm.MOV(asm.r11, asm.operand.MemoryOperand(asm.r10 + 8)))

                    # Fetch the method
                    allocator.encode(asm.MOV(asm.r12, asm.operand.MemoryOperand(asm.r11 + 8 * primitive_offsets_methods[name])))
                    allocator.encode(asm.PUSH(asm.r12))
                else:
                    # TODO: handle the general case for objects
                    self.nyi()

            elif isinstance(instruction, model.COMPARE_OP):
                # COMPARE_OP can't be the last instruction of the block
                next_instruction = block.instructions[i + 1]

                if isinstance(next_instruction, model.JUMP_IF_FALSE_OR_POP):
                    self.compile_cmp_JUMP_IF_FALSE_OR_POP(mfunction, instruction, next_instruction, context)
                elif isinstance(next_instruction, model.JUMP_IF_TRUE_OR_POP):
                    self.compile_cmp_JUMP_IF_TRUE_OR_POP(mfunction, instruction, next_instruction, context)
                elif isinstance(next_instruction, model.POP_JUMP_IF_FALSE):
                    self.compile_cmp_POP_JUMP_IF_FALSE(mfunction, instruction, next_instruction, context)
                elif isinstance(next_instruction, model.POP_JUMP_IF_TRUE):
                    self.compile_cmp_POP_JUMP_IF_TRUE(mfunction, instruction, next_instruction, context)
                else:
                    # General case, we need to put the value on the stack
                    self.compile_cmp(instruction)

                # We already compiled the next instruction which is a branch, the block is fully compiled now
                return return_offset
            elif isinstance(instruction, model.IMPORT_NAME):
                self.nyi()
            elif isinstance(instruction, model.IMPORT_FROM):
                self.nyi()
            elif isinstance(instruction, model.JUMP_FORWARD):
                # Locate the target of the jump
                target_block = None
                for b in block.next:
                    # In case of empty blocks (this should not happened...)
                    if len(b.instructions) == 0:
                        continue

                    if b.instructions[0].offset == instruction.absolute_target:
                        target_block = b

                self.stub_handler.compile_absolute_jump(mfunction, target_block)

            elif isinstance(instruction, model.JUMP_IF_FALSE_OR_POP):
                self.nyi()
            elif isinstance(instruction, model.JUMP_IF_TRUE_OR_POP):
                self.nyi()
            elif isinstance(instruction, model.JUMP_ABSOLUTE):
                # Locate the target of the jump
                target_block = None
                for b in instruction.block.next:
                    # In case of empty blocks (this should not happened...)
                    if len(b.instructions) == 0:
                        continue

                    if b.instructions[0].offset == instruction.argument or len(instruction.block.next) == 1:
                        target_block = b

                self.stub_handler.compile_absolute_jump(mfunction, target_block)

            elif isinstance(instruction, model.POP_JUMP_IF_FALSE):
                self.nyi()
            elif isinstance(instruction, model.POP_JUMP_IF_TRUE):
                self.nyi()
            elif isinstance(instruction, model.LOAD_GLOBAL):

                name = mfunction.names[instruction.argument]

                context.push_value(name)

                # Test if we need to load a class
                if name in stub_handler.primitive_addresses and ("twopy_"+name) in self.class_names:
                    if isinstance(block.instructions[i + 1], model.LOAD_ATTR) or \
                            isinstance(block.instructions[i + 1], model.STORE_ATTR):
                        # Loading the class address
                        allocator.encode(asm.MOV(asm.r10, stub_handler.primitive_addresses[name]))
                        allocator.encode(asm.PUSH(asm.r10))
                        stub_handler.primitive_addresses[name]
                    else:
                        # We need to load the init address here for a future call
                        allocator.encode(asm.MOV(asm.r10, self.initializer_addresses["twopy_"+name]))
                        allocator.encode(asm.PUSH(asm.r10))
                elif name in self.interpreter.global_environment:
                    # Lookup in the global environment
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

            elif isinstance(instruction, model.CONTINUE_LOOP):
                self.nyi()
            elif isinstance(instruction, model.SETUP_LOOP):
                # for now, we don't need to implement this instruction, the compilation will be made with jumps
                pass
            elif isinstance(instruction, model.SETUP_EXCEPT):
                self.nyi()
            elif isinstance(instruction, model.SETUP_FINALLY):
                self.nyi()
            elif isinstance(instruction, model.LOAD_FAST):

                context.push_value(mfunction.varnames[instruction.argument])

                # Load the value and put it onto the stack
                allocator.encode(asm.PUSH(allocator.get_local_variable(instruction.argument, block)))

            elif isinstance(instruction, model.STORE_FAST):
                allocator.encode(asm.POP(asm.r10))

                operand = context.memory_location(instruction.argument, mfunction.varnames[instruction.argument])
                allocator.encode(asm.MOV(operand, asm.r10))

                # Store the variable in the correct position on the stack
            elif isinstance(instruction, model.DELETE_FAST):
                self.nyi()
            elif isinstance(instruction, model.STORE_ANNOTATION):
                self.nyi()
            elif isinstance(instruction, model.RAISE_VARARGS):
                self.nyi()
            elif isinstance(instruction, model.CALL_FUNCTION):

                # Save the function address in r9
                allocator.encode(asm.MOV(asm.r9, asm.operand.MemoryOperand(asm.registers.rsp + 8 * instruction.argument)))

                # The return instruction will clean the stack
                allocator.encode(asm.CALL(asm.r9))

                for y in range(0, instruction.argument + 1):
                    allocator.versioning.current_version().get_context_for_block(block).decrease_stack_size()
                    context.pop_value()

                # The return value is in rax, push it back on the stack
                allocator.encode(asm.PUSH(asm.rax))

                # The return value is unknown
                context.push_value("return_value", objects.Types.Unknown)
            elif isinstance(instruction, model.MAKE_FUNCTION):

                # The name and the code object
                nbargs = 2

                free_variables = None
                if (instruction.argument & 8) == 8:
                    # Making a closure, tuple of free variables
                    pass

                if (instruction.argument & 4) == 4:
                    # Annotation dictionary
                    pass

                if (instruction.argument & 2) == 2:
                    # keyword only default arguments
                    pass

                if (instruction.argument & 1) == 1:
                    # default arguments
                    pass

                # TODO : temporary, the return address will be after the call to the stub
                address = stub_handler.lib.get_address(stub_handler.ffi.from_buffer(self.global_allocator.code_section), self.global_allocator.code_offset + 13)

                stub_address = self.stub_handler.compile_function_stub(mfunction, nbargs, address)

                allocator.encode(asm.MOV(asm.r10, stub_address))
                allocator.encode(asm.CALL(asm.r10))

                context.decrease_stack_size()

            elif isinstance(instruction, model.BUILD_SLICE):
                self.nyi()
            elif isinstance(instruction, model.LOAD_CLOSURE):
                self.nyi()
            elif isinstance(instruction, model.LOAD_DEREF):
                self.nyi()
            elif isinstance(instruction, model.STORE_DEREF):
                self.nyi()
            elif isinstance(instruction, model.DELETE_DEREF):
                self.nyi()
            elif isinstance(instruction, model.CALL_FUNCTION_KW):
                self.nyi()
            elif isinstance(instruction, model.CALL_FUNCTION_EX):
                self.nyi()
            elif isinstance(instruction, model.SETUP_WITH):
                self.nyi()
            elif isinstance(instruction, model.EXTENDED_ARG):
                self.nyi()
            elif isinstance(instruction, model.LIST_APPEND):
                self.nyi()
            elif isinstance(instruction, model.SET_ADD):
                self.nyi()
            elif isinstance(instruction, model.MAP_ADD):
                self.nyi()
            elif isinstance(instruction, model.LOAD_CLASSDEREF):
                self.nyi()
            elif isinstance(instruction, model.BUILD_LIST_UNPACK):
                self.nyi()
            elif isinstance(instruction, model.BUILD_MAP_UNPACK):
                self.nyi()
            elif isinstance(instruction, model.BUILD_MAP_UNPACK_WITH_CALL):
                self.nyi()
            elif isinstance(instruction, model.BUILD_TUPLE_UNPACK):
                self.nyi()
            elif isinstance(instruction, model.BUILD_SET_UNPACK):
                self.nyi()
            elif isinstance(instruction, model.SETUP_ASYNC_WITH):
                self.nyi()
            elif isinstance(instruction, model.FORMAT_VALUE):
                self.nyi()
            elif isinstance(instruction, model.BUILD_CONST_KEY_MAP):
                self.nyi()
            elif isinstance(instruction, model.BUILD_STRING):
                self.nyi()
            elif isinstance(instruction, model.BUILD_TUPLE_UNPACK_WITH_CALL):
                self.nyi()
            elif isinstance(instruction, model.BINARY_TYPE_CHECK):
                # A type-check must be performed for two operands of a binary operation

                # If BBV is deactivated
                if self.interpreter.args.maxvers == 0:
                    print("BBV deactivated ")

                self.tags.binary_type_check(mfunction, block, context)
            else:
                self.nyi()

        block.compiled = True
        block.first_offset = return_offset

        return return_offset

    def compile_load_class(self, allocator, block, i, instruction):
        if isinstance(block.instructions[i + 1], model.LOAD_ATTR) or \
                isinstance(block.instructions[i + 1], model.STORE_ATTR):
            allocator.encode(asm.MOV(asm.r9, allocator.data_address))

            # Offset of the instruction's argument + r9 value
            memory_address = asm.r9 + (64 * instruction.argument)
            allocator.encode(asm.MOV(asm.r10, asm.operand.MemoryOperand(memory_address)))

            allocator.encode(asm.PUSH(asm.r10))
        else:
            # Construct the instance, call new_instance for this class
            allocator.encode(asm.MOV(asm.r9, allocator.data_address))

            # Offset of the instruction's argument + r9 value
            memory_address = asm.r9 + (64 * instruction.argument)
            allocator.encode(asm.MOV(asm.r10, asm.operand.MemoryOperand(memory_address)))
            allocator.encode(asm.SHR(asm.r10, 3))

            # Get the second field in the structure
            allocator.encode(asm.ADD(asm.r10, 8))
            allocator.encode(asm.MOV(asm.r9, asm.operand.MemoryOperand(asm.r10)))
            allocator.encode(asm.PUSH(asm.r9))

    # Compare operators
    compare_operators = ('<', '<=', '==', '!=', '>', '>=', 'in',
                         'not in', 'is', 'is not', 'exception match', 'BAD')

    # Functions used to compile a comparison then a jump after (a if)
    # mfunction : Current compiled function
    # instruction : Current python Bytecode instruction
    # next_instruction : The following instruction
    # context : current context
    def compile_cmp_POP_JUMP_IF_FALSE(self, mfunction, instruction, next_instruction, context):
        self.compile_cmp_beginning(mfunction, context)

        operand0 = context.pop_value()
        operand1 = context.pop_value()

        type0 = operand0[1]
        type1 = operand1[1]

        # The stubs must be compiled before the jumps
        # Get the two following blocks
        jump_block = None
        notjump_block = None

        # Locate the target of the jump in next basic blocks
        for block in instruction.block.next:
            # If we need to make the jump
            if block.instructions[0].offset == next_instruction.argument:
                notjump_block = block
            else:
                # Continue the execution in the second block
                jump_block = block

        # one operand is a float, perform a test for floating point values
        if type0 == objects.Types.Float or type1 == objects.Types.Float:
            if instruction.argument == 0:
                self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JB)
            # first <= second
            elif instruction.argument == 1:
                self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JBE)
            # first == second
            elif instruction.argument == 2:
                self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JE)
            # first != second
            elif instruction.argument == 3:
                self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JNE)
            # first > second
            elif instruction.argument == 4:
                self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JA)
            # first >= second
            elif instruction.argument == 5:
                self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JAE)
            else:
                print("Instruction argument " + str(instruction.argument))
                self.nyi()
        else:
            # Integer operands
            # first < second
            if instruction.argument == 0:
                # Compile stubs for each branch
                self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JL)
            # first <= second
            elif instruction.argument == 1:
                self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JLE)
            # first == second
            elif instruction.argument == 2:
                self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JE)
            # first != second
            elif instruction.argument == 3:
                self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JNE)
            # first > second
            elif instruction.argument == 4:
                self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JG)
            # first >= second
            elif instruction.argument == 5:
                self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JGE)
            else:
                print("Instruction argument " + str(instruction.argument))
                self.nyi()

    #TODO: too much code duplication with the previous function
    # Functions used to compile a comparison then a jump after (a if)
    # mfunction : Current compiled function
    # instruction : Current python Bytecode instruction
    # next_instruction : The following instruction
    # context : current context
    def compile_cmp_POP_JUMP_IF_TRUE(self, mfunction, instruction, next_instruction, context):
        self.compile_cmp_beginning(mfunction, context)

        operand0 = context.pop_value()
        operand1 = context.pop_value()

        type0 = operand0[1]
        type1 = operand1[1]

        # The stubs must be compiled before the jumps
        # Get the two following blocks
        jump_block = None
        notjump_block = None

        # Locate the target of the jump in next basic blocks
        for block in instruction.block.next:
            # If we need to make the jump
            if block.instructions[0].offset == next_instruction.argument:
                jump_block = block
            else:
                # Continue the execution in the second block
                notjump_block = block

        # first < second
        if instruction.argument == 0:
            self.stub_handler.compile_bb_stub(mfunction, notjump_block, jump_block, asm.JGE)
        # first <= second
        elif instruction.argument == 1:
            pass
        # first == second
        elif instruction.argument == 2:
            pass
        # first != second
        elif instruction.argument == 3:
            pass
        # first > second
        elif instruction.argument == 4:
            self.stub_handler.compile_bb_stub(mfunction, jump_block, notjump_block, asm.JG)
        # first >= second
        elif instruction.argument == 5:
            pass
        else:
            print("Instruction argument " + str(instruction.argument))
            self.nyi()

    # Compile the beginning of a COMPARE_OP, pop operands and perform a test in assembly
    # mfunction: currently compiled function
    # context : typing context for this version
    def compile_cmp_beginning(self, mfunction, context):

        operand0 = context.stack[-1]
        operand1 = context.stack[-2]

        type0 = operand0[1]
        type1 = operand1[1]

        if type0 == objects.Types.Float and type1 == objects.Types.Float:
            second_register = asm.r8
            first_register = asm.r9

            # Unbox the values
            mfunction.allocator.encode(asm.POP(second_register))
            mfunction.allocator.encode(self.tags.untag_asm(second_register))

            mfunction.allocator.encode(asm.POP(first_register))
            mfunction.allocator.encode(self.tags.untag_asm(first_register))

            # Move into XMM registers the unboxed values
            mfunction.allocator.encode(asm.MOVQ(asm.xmm0, asm.operand.MemoryOperand(first_register + 8)))
            mfunction.allocator.encode(asm.MOVQ(asm.xmm1, asm.operand.MemoryOperand(second_register + 8)))

            # The argument of the comparison depends of the performed test
            # The COMISD instruction needs to be used with special comparison instructions after
            mfunction.allocator.encode(asm.COMISD(asm.xmm0, asm.xmm1))
        else:
            # Consider we have integers here
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

    # Compilation of special loaded values (__name__ for example)
    # TODO: add something when import is used in the JIT
    def compile_load_special(self, mfunction, name):
        if name == "__name__":
            # Need to determine in which file we are (main one or not)
            # Unicode encoding of the string
            value = "__main__"
            encoded_value = value.encode()
            address = self.global_allocator.allocate_object(encoded_value)

            # Put the tag
            tagged_address = self.tags.tag_string(address)

            # Move this value in a register
            mfunction.allocator.encode(asm.MOV(asm.r10, tagged_address))
            mfunction.allocator.encode(asm.PUSH(asm.r10))

    # Get the __init__ Function from a class definition
    # Return the __init__ function if any, or None if no definition is provided
    # mfunction: the class-function in which we will search the init
    def locate_init(self, mfunction):

        code_init = None

        # Force the creation of the __init__ function if any
        for const in mfunction.consts:
            if isinstance(const, CodeType) and const.co_name == "__init__":
                code_init = const

        if code_init is None:
            return None

        # Generate the init and return it
        return self.interpreter.generate_function(code_init, mfunction.name+"__init__", self.mainmodule, False)

    # Throw an exception if something is not yet implemented
    def nyi(self):
        raise RuntimeError("NOT YET IMPLEMENTED")


# Allocate and handle the compilation of a function
class Allocator:
    def __init__(self, mfunction, jitcompiler, versioning):
        self.function = mfunction
        self.jitcompiler = jitcompiler
        self.versioning = versioning

        # Future code address
        self.code_address = jitcompiler.global_allocator.get_current_address()

        # Future data address
        self.data_address = jitcompiler.global_allocator.get_current_data_address()

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
            self.jitcompiler.init_statistics()

    # Allocate a value and update the environment, this function create an instruction to store the value
    # instruction : The instruction
    # value : the value to allocate
    # context : current compilation context, has to be filled with the constant information
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
            encoded_value = struct.pack("d", value)

            # Allocate the box and tag the address
            address = self.jitcompiler.global_allocator.allocate_object(encoded_value)
            tagged_address = self.jitcompiler.tags.tag_float(address)

            self.encode(asm.MOV(asm.r10, tagged_address))
            self.encode(asm.PUSH(asm.r10))

            context.push_value(value, objects.Types.Float)
        else:
            # For now assume it's consts
            const_object = self.function.consts[instruction.argument]

            if isinstance(const_object, str):
                # Unicode encoding of the string
                encoded_value = const_object.encode()
                address = self.jitcompiler.global_allocator.allocate_object(encoded_value)

                # Put the tag
                tagged_address = self.jitcompiler.tags.tag_string(address)

                # Move this value in a register
                self.encode(asm.MOV(asm.r10, tagged_address))
                self.encode(asm.PUSH(asm.r10))

                self.jitcompiler.consts[tagged_address] = const_object

                context.push_value(const_object, objects.Types.String)
            else:
                # TODO: don't do that for string object, only for code objects
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

        # And the number of arguments and    locals
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

                    # Copy the variable dictionary from previous block
                    context.variable_dict = self.context_map[parent].variable_dict
                    context.stack.extend(self.context_map[parent].stack)

            if context.stack_size < 0:
                context.stack_size = 0

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

        self.variable_dict = {}

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
        if len(self.block.previous) == 0:
            self.stack = []

        # TODO: if we have inter-procedural propagation, initialize the current context with values from the caller

    # TODO: Try to know if a value is duplicated on the stack, in this case store the information
    # Push a value onto the virtual stack
    def push_value(self, value, type_info=objects.Types.Unknown):

        # If we add an unknown value on the stack, try to get its type in local context
        for element in reversed(self.stack):
            if value == element[0] and type_info == objects.Types.Unknown:
                if element[1] != objects.Types.Unknown:
                    type_info = element[1]
                    break

        # Make a tuple of a value and its type
        el = (value, type_info)
        self.stack.append(el)

    # Pop a value from the virtual stack
    def pop_value(self):
        return self.stack.pop()

    # Set a value for a tuple in the virtual stack
    # Try to find duplicate in the stack and set them too
    def set_value(self, tuple, type_value):
        #TODO: find a better solution than this
        variable = tuple[0]

        self.variable_dict[variable] = type_value

        for i in range(len(self.stack)):
            if self.stack[i][0] == variable:
                self.stack[i] = (variable, type_value)


# Static offsets for some primitive functions
# This implements a "static" dispatch for the following names
primitive_offsets_functions = {
    "__twopy__abs": abs,
    "__twopy__dict": dict,
    "__twopy__help": help,
    "__twopy__min": min,
    "__twopy__setattr": setattr,
    "__twopy__all": all,
    "__twopy__dir": dir,
    "__twopy__hex": hex,
    "__twopy__next": next,
    "__twopy__slice": slice,
    "__twopy__any": any,
    "__twopy__divmod": divmod,
    "__twopy__id": id,
    "__twopy__object": object,
    "__twopy__sorted": sorted,
    "__twopy__ascii": ascii,
    "__twopy__enumerate": enumerate,
    "__twopy__input": input,
    "__twopy__oct": oct,
    "__twopy__staticmethod": staticmethod,
    "__twopy__bin": bin,
    "__twopy__eval": eval,
    "__twopy__int": int,
    "__twopy__open": open,
    "__twopy__str": str,
    "__twopy__bool": bool,
    "__twopy__exec": exec,
    "__twopy__isinstance": isinstance,
    "__twopy__ord": ord,
    "__twopy__sum": sum,
    "__twopy__bytearray": bytearray,
    "__twopy__filter": filter,
    "__twopy__issubclass": issubclass,
    "__twopy__pow": pow,
    "__twopy__super": super,
    "__twopy__bytes": bytes,
    "__twopy__float": float,
    "__twopy__iter": 2,
    "__twopy__print": print,
    "__twopy__tuple": tuple,
    "__twopy__callable": callable,
    "__twopy__format": format,
    "__twopy__len": len,
    "__twopy__property": property,
    "__twopy__type": type,
    "__twopy__chr": chr,
    "__twopy__frozenset": frozenset,
    "__twopy__list": list,
    "__twopy__range": range,
    "__twopy__vars": vars,
    "__twopy__classmethod": classmethod,
    "__twopy__getattr": getattr,
    "__twopy__locals": locals,
    "__twopy__repr": repr,
    "__twopy__zip": zip,
    "__twopy__globals": globals,
    "__twopy__map": map,
    "__twopy__reversed": reversed,
    "__twopy____import__": __import__,
    "__twopy__complex": complex,
    "__twopy__hasattr": hasattr,
    "__twopy__max": max,
    "__twopy__round": round,
    "__twopy__hash": hash,
    "__twopy__delattr": delattr,
    "__twopy__memoryview": memoryview,
    "__twopy__set": set,
}


# Primitive offsets for some properties in builtins classes
primitive_offsets_attributes = {
    # Range class
    "twopy_range_start": 3,
    "twopy_range_step": 4,
    "twopy_range_stop": 5,
    "twopy_range_state": 6,
}

# Primitive offsets for some methods in builtins classes
primitive_offsets_methods = {
    # Range class
    "twopy_iter": 5,
    "twopy_next": 6,
}
