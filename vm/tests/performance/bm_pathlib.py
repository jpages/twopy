#!/usr/bin/env python

"""Wrapper script for testing the performance of pathlib operations.

This benchmark stresses the creation of small objects, globbing, and system
calls.
"""

# Python imports
import itertools
import optparse
import os
import shutil
import tempfile
import time

# Local imports
import util
from compat import xrange, izip

# pathlib imports
from pathlib import Path


NUM_FILES = 2000


def generate_files():
    for i in itertools.count():
        for ext in [".py", ".txt", ".tar.gz", ""]:
            yield os.path.join(TMP_PATH, str(i) + ext)


def setup():
    global TMP_PATH
    TMP_PATH = tempfile.mkdtemp()
    for _, fn in izip(xrange(NUM_FILES), generate_files()):
        with open(fn, "w") as f:
            f.write(fn)


def teardown():
    shutil.rmtree(TMP_PATH)


def test_pathlib(count):
    base_path = Path(TMP_PATH)

    # Warm up the filesystem cache and keep some objects in memory.
    path_objects = list(base_path)
    for p in path_objects:
        p.stat()
    assert len(path_objects) == NUM_FILES

    times = []
    for _ in xrange(count // 2):
        t0 = time.time()
        # Do something simple with each path.
        for p in base_path:
            p.st_mtime
        for p in base_path.glob("*.py"):
            p.st_mtime
        for p in base_path:
            p.st_mtime
        for p in base_path.glob("*.py"):
            p.st_mtime
        t1 = time.time()
        times.append(t1 - t0)
    return times


if __name__ == "__main__":
    parser = optparse.OptionParser(
        usage="%prog [options]",
        description=("Test the performance of pathlib operations."))
    util.add_standard_options_to(parser)
    options, args = parser.parse_args()

    setup()
    try:
        util.run_benchmark(options, options.num_runs, test_pathlib)
    finally:
        teardown()
