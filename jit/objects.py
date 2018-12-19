# This module contains the representations used by the JIT compiler


from enum import IntEnum
import peachpy.x86_64 as asm

from jit import stub_handler
from jit import compiler


# Define methods to tag and untag objects
class TagHandler:

    def __init__(self, jit):
        self.jit = jit

    # Tag an integer
    def tag_integer(self, value):
        return value << 3

    # Untag an integer
    def untag_integer(self, value):
        return value >> 3

    # 1010 -> True
    # 0010 -> False
    def tag_bool(self, value):
        tag_value = value << 3
        tag_value = tag_value | Tags.Bool

        return tag_value

    def untag_bool(self, value):
        untag_value = value >> 3
        untag_value = untag_value & 0

        return untag_value

    def tag_object(self, value):
        tag_value = value << 3
        tag_value = tag_value | Tags.MemoryObject

        return tag_value

    def tag_string(self, value):
        tag_value = value << 3
        tag_value = tag_value | Tags.String

        return tag_value

    def tag_float(self, value):
        tag_value = value << 3
        tag_value = tag_value | Tags.Float

        return tag_value

    def tag_float_asm(self, register):
        instructions = [asm.SHL(register, 3), asm.OR(register, Tags.Float)]

        return instructions

    def tag_object_asm(self, register):
        instructions = [asm.SHL(register, 3), asm.OR(register, Tags.MemoryObject)]

        return instructions

    # Untag a value in the given register
    def untag_asm(self, register):
        return asm.SHR(register, 3)

    # Test if the value inside register is an int
    # Return the test sequence as PeachPy instructions in a list
    def is_int_asm(self, register):
        # 7FFF FFFF FFFF FFFF max value for a 64 bits signed integer
        instructions = []

        # Collect stats if needed
        if self.jit.interpreter.args.stats:
            # +1 for each type-check executed
            instructions.append(asm.ADD(self.jit.register_stats, 1))

        # Copy the value inside a new register
        instructions.append(asm.MOV(asm.r12, register))

        test_value = 0b111

        # Now compare
        instructions.append(asm.AND(asm.r12, test_value))

        # The result should be 0 if we have an int
        instructions.append(asm.CMP(asm.r12, 0))

        # Make the jumps according to the result
        return instructions

    # Test if the value inside register is a float
    # Return the test sequence as PeachPy instructions in a list
    def is_float_asm(self, register):

        instructions = list()
        instructions.append(asm.MOV(asm.r12, register))

        instructions.append(asm.AND(asm.r12, Tags.Float))

        instructions.append(asm.CMP(asm.r12, Tags.Float))

        return instructions

    # Compile a type-check for two values, will be followed by a binary operation
    # mfunction : currently compiled function
    # block : the current block
    # context : current context
    def binary_type_check(self, mfunction, block, context):
        # Try to retrieve information on the context stack
        x_register = asm.r13
        y_register = asm.r14

        if self.jit.interpreter.args.maxvers == 0:
            # BBV is deactivated, replace type values with unknow in the virtual stack
            context.variable_types[0] = Types.Unknown
            context.variable_types[1] = Types.Unknown

            new_tuple0 = (context.stack[-1][0], context.variable_types[0])
            new_tuple1 = (context.stack[-2][0], context.variable_types[1])

            context.stack[-1] = new_tuple0
            context.stack[-2] = new_tuple1
        else:
            # Try to retrieve information on types in the context
            context.variable_types[0] = context.stack[-1][1]
            if context.variable_types[0] == Types.Unknown:
                # Try to see in context.variables_dict
                if context.stack[-1][0] in context.variable_dict:
                    context.variable_types[0] = context.variable_dict[context.stack[-1][0]]

            context.variable_types[1] = context.stack[-2][1]
            if context.variable_types[1] == Types.Unknown:
                if context.stack[-2][0] in context.variable_dict:
                    context.variable_types[1] = context.variable_dict[context.stack[-2][0]]

        context.variables_allocation[0] = x_register
        context.variables_allocation[1] = y_register

        # If we have static information on these types, we will compile a stub to the next block
        if context.variable_types[0] != Types.Unknown and context.variable_types[1] != Types.Unknown:
            # Update the stack and directly compile the next block

            # Construct two new tuples to fill the context with up to date information
            new_tuple0 = (context.stack[-1][0], context.variable_types[0])
            new_tuple1 = (context.stack[-2][0], context.variable_types[1])

            context.stack[-1] = new_tuple0
            context.stack[-2] = new_tuple1

            # We should have only one block after
            assert len(block.next) == 1

            for el in block.next:
                self.jit.compile_instructions(mfunction, el)
        else:
            # Move values into registers and keep them on the stack until the end of the test
            instructions = []
            instructions.append(asm.MOV(x_register, asm.operand.MemoryOperand(asm.registers.rsp)))
            instructions.append(asm.MOV(y_register, asm.operand.MemoryOperand(asm.registers.rsp + 8)))

            # Generate a test for the first variable
            test_instructions = self.is_int_asm(x_register)
            instructions.extend(test_instructions)

            # Code for true and false branches
            true_branch = self.is_int_asm(y_register)
            false_branch = self.is_float_asm(x_register)

            # Indicate which operand has to be tested
            id_var = 0
            if context.variable_types[0] != Types.Unknown:
                id_var = 1

            stub = stub_handler.StubType(mfunction, instructions, true_branch, false_branch, id_var, context)

            next_block = None
            for el in block.next:
                next_block = el

            # Indicate to the stub, which block must be compiled after the resolution of the test
            stub.following_block(next_block)

    # Continue the compilation of the test with a context
    # This method is called multiple times through the test, return None when the test if finished
    # context : the context filled with type information
    # mfunction : currently compiled function
    # old_stub : The stub which called this function
    def compile_test(self, context, mfunction, old_stub):

        x_type = context.variable_types[0]
        y_type = context.variable_types[1]

        # Test if we have some information on types
        if x_type == Types.Int:
            if y_type == Types.Unknown:
                # Save registers for the whole test
                for ins in self.is_int_asm(context.variables_allocation[1]):
                    mfunction.allocator.encode(ins)
            elif y_type == Types.Float:
                # Convert x to float and add
                pass
            elif y_type == Types.Int:
                # The test if finished
                pass
        elif x_type == Types.Float:
            if y_type == Types.Unknown:
                instructions = list()

                # Generate a test for the y variable
                test_instructions = self.is_int_asm(context.variables_allocation[1])
                instructions.extend(test_instructions)

                # Code for true and false branches
                true_branch = self.is_int_asm(context.variables_allocation[1])
                false_branch = self.is_float_asm(context.variables_allocation[1])

                stub = stub_handler.StubType(mfunction, instructions, true_branch, false_branch, 1, context)

                # Indicate to the stub, which block must be compiled after the resolution of the test
                stub.following_block(old_stub.next_block)
                return
            elif y_type == Types.Float:
                # Nothing to do here
                pass

        # In the general case, the test is ended, compile instructions after
        old_stub.compile_instructions_after()


# A runtime class
class JITClass:
    def __init__(self, mainfunc, name, *superclasses, metaclass=None):
        self.main_function = mainfunc
        self.name = name
        self.superclasses = superclasses
        self.metaclass = metaclass

        # The vtable will contain all properties (class static variables and methods) of the class
        # | method0 | method1 | attr2 | method3 |
        # It is fill by the compilation of name stores
        self.vtable = ["size", "new_instance"]


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


# TAGS :
# 000    int
# 010    boolean
# 100    memory objects
# 101    float
# 110    strings
class Tags(IntEnum):
    Int = 0b000
    Bool = 0b010
    MemoryObject = 0b100
    Float = 0b101
    String = 0b110
