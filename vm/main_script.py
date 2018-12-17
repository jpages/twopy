#!/usr/bin/python3

import argparse
import subprocess
import os.path

# Execute the compiler with the given arguments
# cmd: the command to execute
# python_file: the python file to execute with Twopy
def run_cmd(cmd, python_file):

    command = cmd + " " + python_file
    subprocess.run(command, shell=True)


def main():
    # Argument parser
    parser = argparse.ArgumentParser(description="Twopy Python compiler")

    # TODO: option usage
    # TODO: all additional options must be passed to twopy
    parser.add_argument('--gdb',
                        help='Enable gdb debugging of Twopy',
                        action='store_true')

    parser.add_argument("python_file", help="Python file to execute")

    parser.add_argument("--time",
                        help="Print the time of the process",
                        action="store_true")

    args = parser.parse_args()

    # Contains arguments for running gdb
    debug_string = ""

    # Used to give env variables to CPython
    env_vars = "PYTHONMALLOC=malloc "

    if args.gdb:
        debug_string = "gdb -ex run --args "

    twopy_entry_point = "twopy.py"

    # Current path
    this_path = os.path.dirname(os.path.realpath(__file__))

    # Make sure to have the correct absolute path, is the project was cloned as expected
    this_path += "/../../cpython/python"

    cmd = env_vars + debug_string + " " + this_path + " " + twopy_entry_point

    if args.time:
        cmd = "time " + cmd

    # run Twopy
    run_cmd(cmd, args.python_file)


if __name__ == '__main__':
    main()
