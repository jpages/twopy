#!/usr/bin/python3.6

import frontend;
import interpreter;

import argparse;

def main():
    # Argument parser
    parser = argparse.ArgumentParser(description = "TwoPy Virtual Machine")
    parser.add_argument("file", help = "path to a python file")

    parser.add_argument("--verbose", "-v", action="store_true",
                        help = "enable verbose output")

    parser.add_argument("--execution", action="store_true",
                        help="Print each variation of the stack during execution")

    args = parser.parse_args()

    # Compile to bytecode and get the module
    module = frontend.compiler.compile(args.file, args)
    vm = interpreter.simple_interpreter.get_interpreter(module, args)

    vm.execute()

main()
