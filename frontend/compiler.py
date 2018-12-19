# Compile python source to bytecode
import py_compile
import marshal
import dis

import importlib.util
import os
import struct
import sys

# Norm for bytecode compilation https://www.python.org/dev/peps/pep-3147/
# New specification of pyc file with python 3.7 https://www.python.org/dev/peps/pep-0552/


# Parse a python bytecode file from an import and return the CodeObject
def compile_import(filename, args):
    # Construct the path of the bytecode file
    head, tail = os.path.split(filename)
    bytecode_path = os.path.join(head, "__pycache__", os.path.splitext(tail)[0]+"."+imp.get_tag()+".pyc")

    # FIXME: test the timestamp of files to check if recompilation is needed

    # If we find a cached version of the source
    if os.path.isfile(bytecode_path):
        # Now check if we need to recompile it
        bytecode_file = open(bytecode_path, "rb")

        # Extract only magic and timestamp
        magic, timestamp = struct.unpack('=II', bytecode_file.read(8))

        # Get the time of the python source file
        source_time = os.path.getmtime(filename)
        diff = source_time - timestamp
        bytecode_file.close()

        # If the python file and bytecode file have the same timestamp
        if diff < 1:
            return parse_file(bytecode_path, args)

    # Otherwise, we must compile it
    return compile_source(filename, args)


# Compile a .py source file to bytecode
def compile_source(filename, args):
    # The normal path of this file if it has been compiled already
    bytecode_filename = importlib.util.cache_from_source(filename)

    # The file exists, now check if the compilation is up to date
    if os.path.exists(bytecode_filename):

        bytecode_file = open(bytecode_filename, "rb")

        magic = bytecode_file.read(4)
        bit_field = bytecode_file.read(4)

        # Check if we have a traditional timestamp-based source file
        if int.from_bytes(bit_field, byteorder=sys.byteorder) == 0:
            tt = bytecode_file.read(4)
            timestamp = struct.unpack("=I", tt)

            # Read the file size
            bytecode_file.read(4)

            # Check timestamps on source and bytecode files
            source_time = os.path.getmtime(filename)

            diff = source_time - timestamp[0]
            # If the python file and bytecode file have the same timestamp
            if diff < 1:
                co = parse_code_object(bytecode_file, args)
                return co

        bytecode_file.close()

    # We compile to the current version of python
    # Force the usage of timestamp for validate pyc file
    mode = py_compile.PycInvalidationMode.TIMESTAMP
    bytecode_filename = py_compile.compile(filename, optimize=0, invalidation_mode=mode)

    return parse_file(bytecode_filename, args)


# Parse a python bytecode file and return the CodeObject
def parse_file(filename, args):
    bytecode_file = open(filename, "rb")

    # The header of a bytecode file is 16 bytes long
    magic = bytecode_file.read(4)
    bit_field = bytecode_file.read(4)
    timestamp = bytecode_file.read(4)
    misc = bytecode_file.read(4)

    return parse_code_object(bytecode_file, args)


# Parse a CodeObject from an already opened file
def parse_code_object(file, args):
    # Then we found the marshaled code object
    body = file.read()
    co = marshal.loads(body)

    if args.verbose:
        print(dis.dis(co))

    file.close()
    return co
