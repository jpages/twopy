#!/usr/bin/env python

"""Microbenchmark for method call overhead where the target is unpredictable.

This measures simple method calls that are unpredictable, but do not use
varargs or kwargs, and do not use tuple unpacking.  This is accomplished by
having three identical classes with four methods that call each other
recursively.  To make the type of the invocant unpredictable, the arguments are
rotated for each method call.  On the first run of a method, all the call sites
will use one type, and on the next, they will all be different.
"""

# Python imports
import optparse
import time

# Local imports
import util
from compat import xrange


class Foo(object):

    def foo(a, b, c):
        # 20 calls
        b.bar(a, c)
        b.bar(c, a)
        c.bar(a, b)
        c.bar(b, a)
        b.bar(a, c)
        b.bar(c, a)
        c.bar(a, b)
        c.bar(b, a)
        b.bar(a, c)
        b.bar(c, a)
        c.bar(a, b)
        c.bar(b, a)
        b.bar(a, c)
        b.bar(c, a)
        c.bar(a, b)
        c.bar(b, a)
        b.bar(a, c)
        b.bar(c, a)
        c.bar(a, b)
        c.bar(b, a)

    def bar(a, b, c):
        # 20 calls
        b.baz(a, c)
        b.baz(c, a)
        c.baz(a, b)
        c.baz(b, a)
        b.baz(a, c)
        b.baz(c, a)
        c.baz(a, b)
        c.baz(b, a)
        b.baz(a, c)
        b.baz(c, a)
        c.baz(a, b)
        c.baz(b, a)
        b.baz(a, c)
        b.baz(c, a)
        c.baz(a, b)
        c.baz(b, a)
        b.baz(a, c)
        b.baz(c, a)
        c.baz(a, b)
        c.baz(b, a)

    def baz(a, b, c):
        # 20 calls
        b.quux(a, c)
        b.quux(c, a)
        c.quux(a, b)
        c.quux(b, a)
        b.quux(a, c)
        b.quux(c, a)
        c.quux(a, b)
        c.quux(b, a)
        b.quux(a, c)
        b.quux(c, a)
        c.quux(a, b)
        c.quux(b, a)
        b.quux(a, c)
        b.quux(c, a)
        c.quux(a, b)
        c.quux(b, a)
        b.quux(a, c)
        b.quux(c, a)
        c.quux(a, b)
        c.quux(b, a)

    def quux(a, b, c):
        # 20 calls
        b.qux(a, c)
        b.qux(c, a)
        c.qux(a, b)
        c.qux(b, a)
        b.qux(a, c)
        b.qux(c, a)
        c.qux(a, b)
        c.qux(b, a)
        b.qux(a, c)
        b.qux(c, a)
        c.qux(a, b)
        c.qux(b, a)
        b.qux(a, c)
        b.qux(c, a)
        c.qux(a, b)
        c.qux(b, a)
        b.qux(a, c)
        b.qux(c, a)
        c.qux(a, b)
        c.qux(b, a)

    def qux(a, b, c):
        pass


class Bar(object):

    def foo(a, b, c):
        # 20 calls
        b.bar(a, c)
        b.bar(c, a)
        c.bar(a, b)
        c.bar(b, a)
        b.bar(a, c)
        b.bar(c, a)
        c.bar(a, b)
        c.bar(b, a)
        b.bar(a, c)
        b.bar(c, a)
        c.bar(a, b)
        c.bar(b, a)
        b.bar(a, c)
        b.bar(c, a)
        c.bar(a, b)
        c.bar(b, a)
        b.bar(a, c)
        b.bar(c, a)
        c.bar(a, b)
        c.bar(b, a)

    def bar(a, b, c):
        # 20 calls
        b.baz(a, c)
        b.baz(c, a)
        c.baz(a, b)
        c.baz(b, a)
        b.baz(a, c)
        b.baz(c, a)
        c.baz(a, b)
        c.baz(b, a)
        b.baz(a, c)
        b.baz(c, a)
        c.baz(a, b)
        c.baz(b, a)
        b.baz(a, c)
        b.baz(c, a)
        c.baz(a, b)
        c.baz(b, a)
        b.baz(a, c)
        b.baz(c, a)
        c.baz(a, b)
        c.baz(b, a)

    def baz(a, b, c):
        # 20 calls
        b.quux(a, c)
        b.quux(c, a)
        c.quux(a, b)
        c.quux(b, a)
        b.quux(a, c)
        b.quux(c, a)
        c.quux(a, b)
        c.quux(b, a)
        b.quux(a, c)
        b.quux(c, a)
        c.quux(a, b)
        c.quux(b, a)
        b.quux(a, c)
        b.quux(c, a)
        c.quux(a, b)
        c.quux(b, a)
        b.quux(a, c)
        b.quux(c, a)
        c.quux(a, b)
        c.quux(b, a)

    def quux(a, b, c):
        # 20 calls
        b.qux(a, c)
        b.qux(c, a)
        c.qux(a, b)
        c.qux(b, a)
        b.qux(a, c)
        b.qux(c, a)
        c.qux(a, b)
        c.qux(b, a)
        b.qux(a, c)
        b.qux(c, a)
        c.qux(a, b)
        c.qux(b, a)
        b.qux(a, c)
        b.qux(c, a)
        c.qux(a, b)
        c.qux(b, a)
        b.qux(a, c)
        b.qux(c, a)
        c.qux(a, b)
        c.qux(b, a)

    def qux(a, b, c):
        pass


class Baz(object):

    def foo(a, b, c):
        # 20 calls
        b.bar(a, c)
        b.bar(c, a)
        c.bar(a, b)
        c.bar(b, a)
        b.bar(a, c)
        b.bar(c, a)
        c.bar(a, b)
        c.bar(b, a)
        b.bar(a, c)
        b.bar(c, a)
        c.bar(a, b)
        c.bar(b, a)
        b.bar(a, c)
        b.bar(c, a)
        c.bar(a, b)
        c.bar(b, a)
        b.bar(a, c)
        b.bar(c, a)
        c.bar(a, b)
        c.bar(b, a)

    def bar(a, b, c):
        # 20 calls
        b.baz(a, c)
        b.baz(c, a)
        c.baz(a, b)
        c.baz(b, a)
        b.baz(a, c)
        b.baz(c, a)
        c.baz(a, b)
        c.baz(b, a)
        b.baz(a, c)
        b.baz(c, a)
        c.baz(a, b)
        c.baz(b, a)
        b.baz(a, c)
        b.baz(c, a)
        c.baz(a, b)
        c.baz(b, a)
        b.baz(a, c)
        b.baz(c, a)
        c.baz(a, b)
        c.baz(b, a)

    def baz(a, b, c):
        # 20 calls
        b.quux(a, c)
        b.quux(c, a)
        c.quux(a, b)
        c.quux(b, a)
        b.quux(a, c)
        b.quux(c, a)
        c.quux(a, b)
        c.quux(b, a)
        b.quux(a, c)
        b.quux(c, a)
        c.quux(a, b)
        c.quux(b, a)
        b.quux(a, c)
        b.quux(c, a)
        c.quux(a, b)
        c.quux(b, a)
        b.quux(a, c)
        b.quux(c, a)
        c.quux(a, b)
        c.quux(b, a)

    def quux(a, b, c):
        # 20 calls
        b.qux(a, c)
        b.qux(c, a)
        c.qux(a, b)
        c.qux(b, a)
        b.qux(a, c)
        b.qux(c, a)
        c.qux(a, b)
        c.qux(b, a)
        b.qux(a, c)
        b.qux(c, a)
        c.qux(a, b)
        c.qux(b, a)
        b.qux(a, c)
        b.qux(c, a)
        c.qux(a, b)
        c.qux(b, a)
        b.qux(a, c)
        b.qux(c, a)
        c.qux(a, b)
        c.qux(b, a)

    def qux(a, b, c):
        pass


def test_calls(iterations):
    times = []
    a = Foo()
    b = Bar()
    c = Baz()
    for _ in xrange(iterations):
        t0 = time.time()
        # 18 calls
        a.foo(b, c)
        b.foo(c, a)
        c.foo(a, b)
        a.foo(b, c)
        b.foo(c, a)
        c.foo(a, b)
        a.foo(b, c)
        b.foo(c, a)
        c.foo(a, b)
        a.foo(b, c)
        b.foo(c, a)
        c.foo(a, b)
        a.foo(b, c)
        b.foo(c, a)
        c.foo(a, b)
        a.foo(b, c)
        b.foo(c, a)
        c.foo(a, b)
        t1 = time.time()
        times.append(t1 - t0)
    return times


if __name__ == "__main__":
    parser = optparse.OptionParser(
        usage="%prog [options] [test]",
        description=("Test the performance of unpredictable Python-to-Python"
                     " method calls."))
    util.add_standard_options_to(parser)
    options, _ = parser.parse_args()

    # Priming run.
    test_calls(1)

    util.run_benchmark(options, options.num_runs, test_calls)
