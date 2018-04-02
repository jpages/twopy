#! /usr/bin/env python

# File: run_tests.py

import sys
import os
import time
import subprocess

#------------------------------------------------------------------------------

# Python interpreters used for testing

ref_interp = ['python3']
interp = ['../../twopy.py']

#------------------------------------------------------------------------------

# Get list of all tests to run in specified directories

def get_tests(dirs):

    tests = []

    def visit(path, ignore):
        if path in ignore:
            return
        if os.path.isdir(path):
            py_file = os.path.join(path, os.path.basename(path)+'.py')
            if os.path.exists(py_file):
                tests.append(py_file)
            else:
                new_ignore = []
                ignore_file = os.path.join(path, '.ignore')
                if os.path.exists(ignore_file):
                    with open(ignore_file, 'r') as f:
                        new_ignore = list(map(lambda x: os.path.join(path, x),
                                              f.read().splitlines()))
                for f in os.listdir(path):
                    visit(os.path.join(path, f), ignore + new_ignore)
        elif path.endswith('.py'):
            tests.append(path)

    for dir in dirs:
        visit(dir, [])

    return tests

#------------------------------------------------------------------------------

# Show progress of testing

bar_length = 20

start_clock = 0.0

nb_tests = 0
nb_succeed = 0
nb_fail = 0

black_text = '\33[0m'
green_text = '\33[32;1m'
red_text = '\33[31;1m'
erase_to_eol = '\33[K'

def output(text):
    sys.stdout.write(text)

def output_flush():
    sys.stdout.flush()

def output_line():
    output('------------------------------------------------------------------------------\n')

def show_progress():

    def ratio(full):
        return full * (nb_succeed+nb_fail) // nb_tests

    progress = ratio(bar_length)

    elapsed_ms = int(time.clock() - start_clock)

    output('\r[{}{:4d}{}|{}{:4d}{}] {}{} {:3d}% {}.{}s{}'
           .format(green_text, nb_succeed, black_text,
                   red_text, nb_fail, black_text,
                   '#' * progress,
                   '.' * (bar_length-progress),
                   ratio(100),
                   elapsed_ms//1000, (elapsed_ms//100)%10,
                   erase_to_eol))

def run_tests(tests):

    global start_clock, nb_tests, nb_succeed, nb_fail

    if len(tests) == 0:
        output('NO TESTS TO RUN!\n')
        sys.exit(1)

    start_clock = time.clock()

    nb_tests = len(tests)
    nb_succeed = 0
    nb_fail = 0

    output_line()
    show_progress()

    for t in tests:
        run_test(t)
        show_progress()

    output('\n')
    output_line()

def get_expected(test):
    with open(test, 'rb') as f:
        content = f.read()
    expected = None
    pos = len(content)
    i = pos
    if i > 0 and content[i-1:i] == b'\n':
        i -= 1
    while True:
        while i > 0 and content[i-1:i] != b'\n': # search line start
            i -= 1
        if content[i:i+1] != b'#': # line doesn't start with '#'?
            break
        if expected is None:
            expected = b''
        expected = content[i+1:pos] + expected
        pos = i
        i -= 1
    return (content[0:pos], expected)

def set_expected(test, expected):
    ex = get_expected(test)
    commented = b'\n#'
    if len(expected) == 0 or expected[-1:] != b'\n':
        commented += expected.replace(b'\n', b'\n#')
    else:
        commented += expected[:-1].replace(b'\n', b'\n#') + expected[-1:]
    new_content = ex[0] + commented
    if ex[1] is not None:
        reply = str(raw_input('really replace expected output of ' + test + ' (y/n): ')).lower().strip()
        if reply[0] != 'y':
            return
    with open(test, 'wb') as f:
        f.write(new_content)

def run_test(test):

    def fail():
        global nb_fail
        nb_fail += 1

    def succeed():
        global nb_succeed
        nb_succeed += 1

    test_dir = os.path.dirname(test)

    if test.startswith(common_dir):
        name = test[len(common_dir):]
    else:
        name = test
    output(' ' + name)
    output_flush()

    ex = get_expected(test)

    if ex[1] is None:
        if fix_expected:
            ref_result = run(ref_interp + [test], test_dir)
            if ref_result[0] == 0:
                set_expected(test, ref_result[1])
            else:
                print('\ncannot set expected result of crashing test '+test)
                sys.exit(1)
        else:
            output(' *MISSING EXPECTED RESULT*\n')
            output_line()
            fail()
            return
    else:
        ref_result = (0, ex[1])

    result = run(interp + [test], test_dir)

    if result == ref_result:
        # same termination status and same stdout
        succeed()
    elif result[0] == ref_result[0] and ref_result[0] != 0:
        # same termination status != 0
        succeed()
    else:
        output(' *FAIL*\n')
        output('*********** GOT STATUS=' + str(result[0]) + '\n')
        output(result[1].decode('iso8859-1'))
        output('*********** EXPECTED STATUS=' + str(ref_result[0]) + '\n')
        output(ref_result[1].decode('iso8859-1'))
        output_line()
        fail()

def run(cmd, cwd):
    stdin_path = os.path.join(cwd, 'stdin')
    if os.path.exists(stdin_path):
        stdin = open(stdin_path, 'r')
    else:
        stdin = subprocess.PIPE
    p = subprocess.Popen(cmd, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True, cwd=cwd)
    if stdin is subprocess.PIPE:
        p.stdin.close()
    else:
        stdin.close()
    result = p.stdout.read()
    code = p.wait()
    return (code,result)

#------------------------------------------------------------------------------

# Main

dirs = []
common_dir = None
fix_expected = False

def add_dir(path):

    global common_dir

    if not os.path.isdir(path):
        output(path + ' is not a directory')
        sys.exit(1)
    else:
        dir = os.path.join(os.path.abspath(path), '')
        dirs.append(dir)
        if common_dir is None:
            common_dir = dir
        else:
            common_prefix = os.path.commonprefix([dir, common_dir])
            common_dir = os.path.join(os.path.dirname(common_prefix), '')

def main():

    global ref_interp, interp, fix_expected

    i = 1

    while i < len(sys.argv):
        arg = sys.argv[i]
        i += 1
        if arg == '-fix_expected':
            fix_expected = True
            continue
        elif i < len(sys.argv):
            arg2 = sys.argv[i]
            if arg == '-interp':
                interp = arg2.split()
                i += 1
                continue
            elif arg == '-ref_interp':
                ref_interp = arg2.split()
                i += 1
                continue
        add_dir(arg)

    if len(dirs) == 0:
        add_dir(os.path.join(os.path.dirname(sys.argv[0]), 'unit_tests'))

    run_tests(get_tests(dirs))

if __name__ == '__main__':
    main()

#------------------------------------------------------------------------------

# -*- mode: Python; python-indent-offset: 4; python-guess-indent: nil -*-
