#! /usr/bin/env python

import frontend
import interpreter
import jit

import argparse
import os.path

def main():
    # Argument parser
    parser = argparse.ArgumentParser(description="Twopy Virtual Machine")
    parser.add_argument("file", help="path to a python file")

    parser.add_argument("--verbose", "-v", action="store_true",
                        help="enable verbose output")

    parser.add_argument("--execution", action="store_true",
                        help="Print each variation of the stack during execution")

    parser.add_argument("--inter", action="store_true",
                        help="Interpretation of the code")

    parser.add_argument("--asm", action="store_true",
                        help="Print generated assembly code")

    parser.add_argument("--maxvers", type=int,
                        help="Maximum number of generated versions for BBV.\n0 means infinite versions, default is 5.")

    parser.add_argument("--no_std_lib", action="store_true",
                        help="Do not compile the standard library of Twopy. Not much will be executable.")

    parser.add_argument("--stats", action="store_true",
                        help="Collect statistics on execution")

    parser.add_argument("--compile_ffi", action="store_true",
                        help="Compile the C-FFI used by Twopy")

    args = parser.parse_args()

    # Compile to bytecode and get the main CodeObject
    maincode = frontend.compiler.compile_source(args.file, args)

    # Get the subdirectory of the executed file
    head, tail = os.path.split(args.file)
    inter = interpreter.simple_interpreter.get_interpreter(maincode, head, args)

    if args.inter:
        inter.execute()
    else:
        jitcompiler = jit.compiler.JITCompiler(inter, maincode)
        inter.jitcompiler = jitcompiler
        jitcompiler.execute()

main()
