#!/usr/bin/env python

"""Benchmark how quickly Python's regex implementation can compile regexes.

We bring in all the regexes used by the other regex benchmarks, capture them by
stubbing out the re module, then compile those regexes repeatedly. We muck with
the re module's caching to force it to recompile every regex we give it.
"""

# Python imports
import optparse
import re
import time

# Local imports
import util
from compat import xrange


def capture_regexes():
    regexes = []

    real_compile = re.compile
    real_search = re.search
    real_sub = re.sub

    def capture_compile(regex, flags=0):
        regexes.append((regex, flags))
        return real_compile(regex, flags)

    def capture_search(regex, target, flags=0):
        regexes.append((regex, flags))
        return real_search(regex, target, flags)

    def capture_sub(regex, *args):
        regexes.append((regex, 0))
        return real_sub(regex, *args)

    re.compile = capture_compile
    re.search = capture_search
    re.sub = capture_sub
    try:
        import bm_regex_effbot
        bm_regex_effbot.test_regex_effbot(1)

        import bm_regex_v8
        bm_regex_v8.test_regex_v8(1)
    finally:
        re.compile = real_compile
        re.search = real_search
        re.sub = real_sub
    return regexes


def test_regex_compile(count):
    try:
        clear_cache = re._cache.clear
    except AttributeError:
        try:
            # Python 3.2: re._compile_typed() uses functools.lru_cache()
            clear_cache = re._compile_typed.cache_clear
        except AttributeError:
            # Python 3.3: re._compile() uses functools.lru_cache()
            clear_cache = re._compile.cache_clear

    regexes = capture_regexes()
    times = []

    for _ in xrange(count):
        t0 = time.time()
        for regex, flags in regexes:
            clear_cache()
            re.compile(regex, flags)
        t1 = time.time()
        times.append(t1 - t0)
    return times


if __name__ == "__main__":
    parser = optparse.OptionParser(
        usage="%prog [options]",
        description=("Test regex compilation performance"))
    util.add_standard_options_to(parser)
    options, args = parser.parse_args()

    util.run_benchmark(options, options.num_runs, test_regex_compile)