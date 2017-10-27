# Compile python source to bytecode
import py_compile
import marshal
import dis

import imp
import os

# Norm for bytecode compilation https://www.python.org/dev/peps/pep-3147/

# Parse a python bytecode file from an import and return the CodeObject
def compile_import(filename, args):
    # Construct the path of the bytecode file
    head, tail = os.path.split(filename)
    bytecode_file = os.path.join(head, "__pycache__", os.path.splitext(tail)[0]+"."+imp.get_tag()+".pyc")

    # FIXME: test the timestamp of files to check if recompilation is needed

    # If we find a cached version of the source
    if os.path.isfile(bytecode_file):
        return parse_file(bytecode_file, args)
    else:
        # We must compile it
        return compile(filename, args)

# TODO: implement the same behavior as compile_import
# Compile a .py source file to bytecode
def compile(filename, args):
    # We compile to the current version of python
    bytecode_filename = py_compile.compile(filename, optimize = 0)
    return parse_file(bytecode_filename, args)

# Parse a python bytecode file and return the CodeObject
def parse_file(filename, args):
    bytecode_file = open(filename, "rb")

    # The header of a bytecode file is 12 bytes long
    magic = bytecode_file.read(4)
    timestamp = bytecode_file.read(4)
    misc = bytecode_file.read(4)

    # Then we found the marshaled code object
    body = bytecode_file.read()
    co = marshal.loads(body)

    if args.verbose:
        print(dis.dis(co))

    bytecode_file.close()
    return co
