#!/usr/bin/python3

import argparse
import subprocess
import os.path
import glob

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

    # Run benchmarks and exit
    parser.add_argument("--benchs", "--benchmarks",
                        help="Run all benchmarks in benchmarks/ directory and exit",
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
    this_path += "/../cpython/python"

    cmd = env_vars + debug_string + " " + this_path + " " + twopy_entry_point

    if args.time:
        cmd = "time " + cmd

    # This option launches twopy on every benchmark then exit
    if args.benchs:
        bench_dir = os.path.dirname(os.path.realpath(__file__)) + "/benchmarks/"
        bench_list = glob.glob(bench_dir + "*.py")

        # Automatically add the time
        if not args.time:
            cmd = "time " + cmd

        # Execute each file
        for file in bench_list:
            print(file)
            run_cmd(cmd, file)
    else:
        # run Twopy
        run_cmd(cmd, args.python_file)


if __name__ == '__main__':
    main()
