import peachpy

#THIS IS A TEST FILE

# rename for better code visibility
import peachpy.x86_64 as asm

import cffi

def main():
    x = peachpy.Argument(peachpy.int64_t)
    y = peachpy.Argument(peachpy.int64_t)

    # Test function which add two values
    with asm.Function("Add", (x, y), peachpy.int64_t) as asm_function:

        reg_x = asm.GeneralPurposeRegister64()
        reg_y = asm.GeneralPurposeRegister64()

        asm.LOAD.ARGUMENT(reg_x, x)
        asm.LOAD.ARGUMENT(reg_y, y)

        asm.ADD(reg_x, reg_y)

        asm.RETURN(reg_x)

    python_function_finalize = asm_function.finalize(asm.abi.detect())
    encoded_function = python_function_finalize.encode()
    loaded_function = encoded_function.load()

    print(loaded_function(2, 4))

    # Source code of C functions
    ffi = cffi.FFI()

    # C Header
    ffi.cdef(""" 
        int foo(int a);
        int stub_function(int id_stub);
    """)

    # C Sources
    ffi.set_source("stub_module", """
        #include <stdio.h>
        
        int foo(int a)
        {
            printf("a = %d\\n", a);
            a = a + 2;
        
            return a;
        }
        
        int stub_function(int id_stub)
        {
            return id_stub;
        }
    """)

    # Now compile this and create python wrapper
    ffi.compile()

    # Import of the generated python module
    from stub_module import ffi, lib

    print("Call to foo : " + str(lib.foo(10)))
    print("Address of foo : " + str(ffi.addressof(lib, "foo")))

    # Calling an assembly function from an assembly function
    id_stub = peachpy.Argument(peachpy.int64_t)
    with asm.Function("stub", (id_stub,), peachpy.int64_t) as stub_function:

        reg_id = asm.GeneralPurposeRegister64()
        asm.LOAD.ARGUMENT(reg_id, id_stub)

        # Calling convention of x86_64 on linux platforms
        # TODO: don't use hard-code register for the address

        # Call to another compiled peachpy function
        #asm.MOV(asm.r15, loaded_function.loader.code_address)

        # Call to a C FFI function with one parameter
        asm.MOV(asm.r15, int(ffi.cast("intptr_t", ffi.addressof(lib, "foo"))))
        asm.MOV(asm.rdi, reg_id)

        # If a second parameter is needed
        #asm.MOV(asm.rsi, 5)

        asm.CALL(asm.r15)

        asm.RETURN()

    stub_compiled_function = stub_function.finalize(asm.abi.detect()).encode().load()
    print(stub_compiled_function(10))

main()
