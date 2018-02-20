'''
This module contains the representations used by the JIT compiler
'''

import sys
import peachpy.x86_64 as asm

# Define methods to tag and untag objects
class TagHandler:

    # TAGS :
    # 00    int
    # 01    specials like char and boolean
    # 10    memory objects
    def __init__(self):
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

    # Untag a value in the given register
    def untag_asm(self, register):
        return asm.SHR(register, 2)

    # Test if the value inside register is an int
    def is_int_asm(self, register):
        # 7FFF FFFF FFFF FFFF max value for a 64 bits signed integer
        max_value = sys.maxsize

        instructions = []

        # FFFF FFFF FFFF FFFC = max value with the tag applied
        # test with 0b11, if we have 0, then we have an integer
        instructions.append(asm.MOV(asm.r11, 0xFFFFFFFFFFFFFFFC))

        # Copy the value inside a new register
        instructions.append(asm.MOV(asm.r12, register))

        test_value = 0b11

        # Now compare
        instructions.append(asm.AND(register, test_value))

        # The result should be 0 if we have an int
        instructions.append(asm.CMP(register, 0))

        # Make the jumps according to the result
        return instructions

    # Handle all binary operations and check types
    def binary_operation(self, opname):
        instructions = []

        # First operand in r9

        x_register = asm.r9
        y_register = asm.r10

        instructions.append(asm.POP(x_register))
        instructions.append(asm.POP(y_register))

        if self.is_int_asm(x_register):
            if self.is_int_asm(y_register):
                # TODO: Check overflow
                # res = add_int_overflow(x, y)

                # Just add the two integers
                instructions.append(asm.ADD(x_register, y_register))
                return instructions
            else:
                # Convert x to float and add
                return add_float(int_to_float(x), y)
        elif is_float(x):
            if if_int(y):
                return add_float(x, int_to_float(y))
            elif is_float(y):
                return add_float(x, y)

        # TODO: General case, call the + function from standard library
        return x.__add__(y)


class Object:
    def __init__(self):
        pass


class Numeric(Object):
    def __init__(self):
        pass


class Integer(Numeric):
    def __init__(self):
        pass


class Float(Numeric):
    def __init__(self):
        pass