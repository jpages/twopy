'''
This module contains the representations used by the JIT compiler
'''

import sys
from enum import IntEnum
import peachpy.x86_64 as asm

from . import stub_handler
from . import compiler

# Define methods to tag and untag objects
class TagHandler:

    # TAGS :
    # 00    int
    # 01    specials like char and boolean
    # 10    memory objects
    def __init__(self, jit):
        self.jit = jit
        #TODO: define relation betweens types and their tags
        pass

    # Tag an integer
    def tag_integer(self, value):
        return value << 2

    # Untag an integer
    def untag_integer(self, value):
        return value >> 2

    # 101 -> True
    # 001 -> False
    def tag_bool(self, value):
        tag_value = value << 2
        tag_value = tag_value | 1

        return tag_value

    def untag_bool(self, value):
        untag_value = value >> 2
        untag_value = untag_value & 0

        return untag_value

    def tag_object(self, value):
        tag_value = value << 2
        tag_value = tag_value | 3

        return tag_value

    #TODO: untag_function for objects

    # Untag a value in the given register
    def untag_asm(self, register):
        return asm.SHR(register, 2)

    # Test if the value inside register is an int
    # Return the test sequence as PeachPy instructions in a list
    def is_int_asm(self, register):
        # 7FFF FFFF FFFF FFFF max value for a 64 bits signed integer
        instructions = []

        # FFFF FFFF FFFF FFFC = max value with the tag applied

        # Copy the value inside a new register
        instructions.append(asm.MOV(asm.r12, register))

        test_value = 0b11

        # Now compare
        instructions.append(asm.AND(asm.r12, test_value))

        # The result should be 0 if we have an int
        instructions.append(asm.CMP(asm.r12, 0))

        # Make the jumps according to the result
        return instructions

    # Test if the value inside register is a float
    # Return the test sequence as PeachPy instructions in a list
    def is_float_asm(self, register):
        return None

    # Handle all binary operations and check types
    # opname : name of the binary operation
    # mfunction : currently compiled function
    # block : the current block
    # next_index of the next instruction to compile, after the type-test
    # TODO: for now only handle addition
    def binary_operation(self, opname, mfunction, block, next_index):
        instructions = []

        x_register = asm.r13
        y_register = asm.r14

        context = mfunction.allocator.versioning.current_version().get_context_for_block(block)

        # TODO: Try to retrieve information on the top two values in virtual stack
        context.variable_types[0] = context.stack[-1][1]
        context.variable_types[1] = context.stack[-2][1]

        context.variables_allocation[0] = x_register
        context.variables_allocation[1] = y_register

        # Directly compile the operation
        if context.variable_types[0] != Types.Unknown and context.variable_types[1] != Types.Unknown:
            instructions = self.compile_test(context, opname)
            for i in instructions:
                mfunction.allocator.encode(i)

            # In this case only, ask for the compilation of the remaining instructions in the block
            if opname in compiler.JITCompiler.compare_operators:
                stub_handler.jitcompiler_instance.compile_instructions(mfunction, block, next_index)
        else:
            # Move values into registers and keep them on the stack until the end of the test
            instructions.append(asm.MOV(x_register, asm.operand.MemoryOperand(asm.registers.rsp)))
            instructions.append(asm.MOV(y_register, asm.operand.MemoryOperand(asm.registers.rsp + 8)))

            # Generate a test for the first variable
            test_instructions = self.is_int_asm(x_register)
            instructions.extend(test_instructions)

            # Code for true and false branchs
            true_branch = self.is_int_asm(y_register)
            false_branch = self.is_float_asm(y_register)

            # Indicate which operand has to be tested
            id_var = 0
            if context.variable_types[0] != Types.Unknown:
                id_var = 1

            stub = stub_handler.StubType(mfunction, instructions, true_branch, false_branch, id_var, context)

            # Indicate to the stub, which operation must be performed after the trigger
            stub.instructions_after(opname, block, next_index)

    # Continue the compilation of the test with a context
    # This method is called multiple times through the test
    # context : the context filled with type informations
    # opname : name of the operand
    # FIXME: dirty fix, find something better here
    # from_callback : Indicate if this function is called from a callback
    def compile_test(self, context, opname, from_callback=False):

        x_type = context.variable_types[0]
        y_type = context.variable_types[1]

        # Test if we have some informations on types
        if x_type == Types.Int:
            if y_type == Types.Unknown:
                #Save registers for the whole test
                return self.is_int_asm(context.variables_allocation[1])
            elif y_type == Types.Float:
                # Convert x to float and add
                return add_float(int_to_float(x), y)
            elif y_type == Types.Int:
                # TODO: Check overflow
                # res = add_int_overflow(x, y)

                # Just add the two integers
                instructions = []

                self.compile_operation(instructions, context, context.variables_allocation[0], context.variables_allocation[1], opname, from_callback)

                return instructions
        elif x_type == Types.Float:
            if if_int(y):
                return add_float(x, int_to_float(y))
            elif is_float(y):
                return add_float(x, y)

        # TODO: General case, call the + function from standard library
        return x.__add__(y)

    # Compile the operation from two registers and an opname
    def compile_operation(self, instructions, context, reg0, reg1, opname, from_callback=False):
        # Special case for comparison operators
        if opname in compiler.JITCompiler.compare_operators:
            return

        #FIXME
        if from_callback:
            context.decrease_stack_size()
            context.decrease_stack_size()

        instructions.append(asm.POP(context.variables_allocation[1]))
        instructions.append(asm.POP(context.variables_allocation[0]))
        if opname == "add":
            instructions.append(asm.ADD(reg0, reg1))
        elif opname == "sub":
            instructions.append(asm.SUB(reg0, reg1))
        elif opname == "mul":
            # Untag the value to not duplicate the tag
            ins = self.untag_asm(context.variables_allocation[0])
            instructions.append(ins)

            instructions.append(asm.IMUL(reg0, reg1))
        else:
            print("Not yet implemented")

        # Get current instruction offset
        offset = stub_handler.lib.get_address(stub_handler.ffi.from_buffer(self.jit.global_allocator.code_section),
                                              self.jit.global_allocator.code_offset)

        encoded = []
        for i in instructions:
            encoded.append(i.encode())

        # Adding the length of previous instructions in the list and the size of the JO
        offset += len(encoded) + 14

        # Jump to an error handler if overflow
        address_error = stub_handler.stubhandler_instance.compile_error_stub(1)
        diff = address_error - offset

        # For now, jump to a stub which will print an error and exit
        # This need to be replaced with a proper overflow handling and a conversion to bignums
        instructions.append(asm.JO(asm.operand.RIPRelativeOffset(diff)))
        instructions.append(asm.PUSH(reg0))

        # FIXME
        if from_callback:
            context.increase_stack_size()

class Object:
    def __init__(self):
        pass


class Numeric(Object):
    def __init__(self):
        pass


class Integer(Numeric):
    def __init__(self):
        pass


class Bool(Integer):
    def __init__(self):
        pass


class Float(Numeric):
    def __init__(self):
        pass


# Enum class for all types in contexts
class Types(IntEnum):
    Unknown = 0
    Int = 1
    Float = 2
    Bool = 3
    String = 4
