#! /usr/bin/python3

import argparse
import subprocess
import os.path

# Execute the compiler with the given arguments
# cmd: the command to execute
# python_file: the python file to execute with Twopy
def run_cmd(cmd, python_file):

    subprocess.run(cmd + " " + python_file, shell=True)


def main():
    # Argument parser
    parser = argparse.ArgumentParser(description="Twopy Python compiler")

    # Intercept a debug option to run gdb
    # TODO: option usage
    # TODO: option time (of the subprocess)
    # TODO: print the output
    parser.add_argument('--debug', '-gdb',
                        help='Enable gdb debugging of Twopy',
                        action='store_true')

    parser.add_argument("python_file", help="Python file to execute")


    args = parser.parse_args()

    if args.debug:
        print("Debug mode")

    twopy_entry_point = "twopy.py"

    # Current path
    this_path = os.path.dirname(os.path.realpath(__file__))

    # Make sure to have the correct absolute path, is the project was cloned as expected
    this_path += "/../../cpython/python"

    cmd = "PYTHONMALLOC=malloc " + this_path + " " + twopy_entry_point

    print(cmd+"\n")

    # run Twopy
    run_cmd(cmd, args.python_file)


if __name__ == '__main__':
    main()
