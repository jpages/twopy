'''
This module contains the JIT compiler
'''

import peachpy

# rename for better code visibility
import peachpy.x86_64 as asm

# Compile the function  in parameter to binary code
# return the code instance
def compile(function):
    print("Compilation of function " + str(function))

    x = peachpy.Argument(peachpy.int32_t)
    y = peachpy.Argument(peachpy.int32_t)

    with asm.Function("Add", (x, y), peachpy.int32_t) as asm_function:
        reg_x = asm.GeneralPurposeRegister32()
        reg_y = asm.GeneralPurposeRegister32()

        asm.LOAD.ARGUMENT(reg_x, x)
        asm.LOAD.ARGUMENT(reg_y, y)

        asm.ADD(reg_x, reg_y)

        asm.RETURN(reg_x)

    python_function = asm_function.finalize(asm.abi.detect()).encode().load()

    print(python_function(2, 4)) # -> prints "6"
