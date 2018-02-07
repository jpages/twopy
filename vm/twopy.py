#!/usr/bin/python3.6

import frontend
import interpreter
import jit

import argparse
import os.path

def main():
    # Argument parser
    parser = argparse.ArgumentParser(description = "TwoPy Virtual Machine")
    parser.add_argument("file", help = "path to a python file")

    parser.add_argument("--verbose", "-v", action="store_true",
                        help = "enable verbose output")

    parser.add_argument("--execution", action="store_true",
                        help="Print each variation of the stack during execution")

    parser.add_argument("--jit", action="store_true",
                        help="JIT compilation of the code")

    parser.add_argument("--asm", action="store_true",
                        help="Print generated assembly code")

    args = parser.parse_args()

    # Compile to bytecode and get the main CodeObject
    maincode = frontend.compiler.compile(args.file, args)

    # Get the subdirectory of the executed file
    head, tail = os.path.split(args.file)
    inter = interpreter.simple_interpreter.get_interpreter(maincode, head, args)

    if args.jit:
        jitcompiler = jit.compiler.JITCompiler(inter, maincode)
        inter.jitcompiler = jitcompiler
        jitcompiler.execute()
    else:
        inter.execute()

main()
