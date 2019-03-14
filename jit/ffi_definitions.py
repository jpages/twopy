# Contains all functions defined in C used by the standard library or the compiler to make callbacks to python

import cffi

# The following definitions must be top-level to facilitate the interface with C
# Use the CFFI to define C functions which are callable from assembly
ffi = cffi.FFI()

# First add header declarations of all functions related to stubs
with open("jit/stub.h", 'r') as f:
    stub_header = f.read()

ffi.cdef(stub_header)

# Then add headers for the garbage collector module
with open("jit/gc.h", 'r') as f:
    gc_header = f.read()

ffi.cdef(gc_header)

# Then we add the source code of our C modules, first the garbage collector
with open("jit/gc.c", 'r') as f:
    gc_source = f.read()

c_code = gc_source

# Then the sources for the stubs-related functions
with open("jit/stub.c", 'r') as f:
    stub_source = f.read()

c_code += "\n " + stub_source


# C Sources
ffi.set_source("stub_module", c_code)

# Now compile this and create python wrapper
ffi.compile()
