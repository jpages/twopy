#!/usr/bin/env python

"""Script for testing the performance of logging simple messages.
"""

# Python imports
import io
import logging
import optparse
import sys
import time

# Local imports
import util
from compat import xrange

# A simple format for parametered logging
FORMAT = 'important: %s'
MESSAGE = 'some important information to be logged'


def test_no_output(iterations, logger):
    times = []
    m = MESSAGE
    for _ in xrange(iterations):
        t0 = time.time()
        for _ in xrange(10000):
            logger.debug(m)
            logger.debug(m)
            logger.debug(m)
            logger.debug(m)
            logger.debug(m)
            logger.debug(m)
            logger.debug(m)
            logger.debug(m)
            logger.debug(m)
            logger.debug(m)
        t1 = time.time()
        times.append(t1 - t0)
    return times


def test_simple_output(iterations, logger):
    times = []
    m = MESSAGE
    for _ in xrange(iterations):
        t0 = time.time()
        for _ in xrange(1000):
            logger.warn(m)
            logger.warn(m)
            logger.warn(m)
            logger.warn(m)
            logger.warn(m)
            logger.warn(m)
            logger.warn(m)
            logger.warn(m)
            logger.warn(m)
            logger.warn(m)
        t1 = time.time()
        times.append(t1 - t0)
    return times


def test_formatted_output(iterations, logger):
    times = []
    f = FORMAT
    m = MESSAGE
    for _ in xrange(iterations):
        t0 = time.time()
        for _ in xrange(1000):
            logger.warn(f, m)
            logger.warn(f, m)
            logger.warn(f, m)
            logger.warn(f, m)
            logger.warn(f, m)
            logger.warn(f, m)
            logger.warn(f, m)
            logger.warn(f, m)
            logger.warn(f, m)
            logger.warn(f, m)
        t1 = time.time()
        times.append(t1 - t0)
    return times


if __name__ == "__main__":
    parser = optparse.OptionParser(
        usage="%prog [no_output|simple_output|formatted_output] [options]",
        description=("Test the performance of logging."))
    util.add_standard_options_to(parser)
    options, args = parser.parse_args()

    benchmarks = ["no_output", "simple_output", "formatted_output"]
    for bench_name in benchmarks:
        if bench_name in args:
            benchmark = globals()["test_" + bench_name]
            break
    else:
        raise RuntimeError("Need to specify one of %s" % benchmarks)

    # NOTE: StringIO performance will impact the results...
    if sys.version_info >= (3,):
        sio = io.StringIO()
    else:
        sio = io.BytesIO()
    handler = logging.StreamHandler(stream=sio)
    logger = logging.getLogger("benchlogger")
    logger.propagate = False
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING)

    util.run_benchmark(options, options.num_runs, benchmark, logger)

    if benchmark is not test_no_output:
        assert len(sio.getvalue()) > 0
    else:
        assert len(sio.getvalue()) == 0
