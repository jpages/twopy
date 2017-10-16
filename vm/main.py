#!/usr/bin/python3.6

import frontend;
import interpreter;

import argparse;

def main():
    # Argument parser
    parser = argparse.ArgumentParser(description = "TwoPy Virtual Machine")
    parser.add_argument("file", help = "path to a python file")

    # TODO: activate/deactivate a verbose mode
    parser.add_argument("--verbose", "-v",
                        help = "enable verbose output (deactivated for now)")

    args = parser.parse_args()

    # Compile to bytecode and get the module
    module = frontend.compiler.compile(args.file)
    vm = interpreter.simple_interpreter.get_interpreter(module)

    vm.execute()

main()
