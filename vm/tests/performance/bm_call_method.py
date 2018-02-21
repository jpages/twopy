#!/usr/bin/env python

"""Microbenchmark for method call overhead.

This measures simple method calls that are predictable, do not use varargs or
kwargs, and do not use tuple unpacking.
"""

# Python imports
import optparse
import time

# Local imports
import util
from compat import xrange


class Foo(object):

    def foo(self, a, b, c, d):
        # 20 calls
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)
        self.bar(a, b, c)

    def bar(self, a, b, c):
        # 20 calls
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)
        self.baz(a, b)

    def baz(self, a, b):
        # 20 calls
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)
        self.quux(a)

    def quux(self, a):
        # 20 calls
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()
        self.qux()

    def qux(self):
        pass


def test_calls(iterations):
    times = []
    f = Foo()
    for _ in xrange(iterations):
        t0 = time.time()
        # 20 calls
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        f.foo(1, 2, 3, 4)
        t1 = time.time()
        times.append(t1 - t0)
    return times


if __name__ == "__main__":
    parser = optparse.OptionParser(
        usage="%prog [options] [test]",
        description=("Test the performance of simple Python-to-Python method"
                     " calls."))
    util.add_standard_options_to(parser)
    options, _ = parser.parse_args()

    # Priming run.
    test_calls(1)

    util.run_benchmark(options, options.num_runs, test_calls)
