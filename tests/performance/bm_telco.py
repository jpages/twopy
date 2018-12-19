#-*- coding: UTF-8 -*-
""" Telco Benchmark for measuring the performance of decimal calculations

http://www2.hursley.ibm.com/decimal/telco.html
http://www2.hursley.ibm.com/decimal/telcoSpec.html

A call type indicator, c, is set from the bottom (least significant) bit of the duration (hence c is 0 or 1).
A r, r, is determined from the call type. Those calls with c=0 have a low r: 0.0013; the remainder (‘distance calls’) have a ‘premium’ r: 0.00894. (The rates are, very roughly, in Euros or dollarates per second.)
A price, p, for the call is then calculated (p=r*n). This is rounded to exactly 2 fractional digits using round-half-even (Banker’s round to nearest).
A basic tax, b, is calculated: b=p*0.0675 (6.75%). This is truncated to exactly 2 fractional digits (round-down), and the total basic tax variable is then incremented (sumB=sumB+b).
For distance calls: a distance tax, d, is calculated: d=p*0.0341 (3.41%). This is truncated to exactly 2 fractional digits (round-down), and then the total distance tax variable is incremented (sumD=sumD+d).
The total price, t, is calculated (t=p+b, and, if a distance call, t=t+d).
The total prices variable is incremented (sumT=sumT+t).
The total price, t, is converted to a string, s.

"""

import contextlib
from decimal import *
import os
from struct import unpack
import sys
from time import clock as time

from compat import xrange


def rel_path(*path):
    return os.path.join(os.path.dirname(__file__), *path)

test = False

filename = rel_path("data", "telco-bench.b")

def run():
    getcontext().rounding = ROUND_DOWN
    rates = list(map(Decimal, ('0.0013', '0.00894')))
    twodig = Decimal('0.01')
    Banker = Context(rounding=ROUND_HALF_EVEN)
    basictax = Decimal("0.0675")
    disttax = Decimal("0.0341")

    infil = open(filename, "rb")
    start = time()

    sumT = Decimal("0")   # sum of total prices
    sumB = Decimal("0")   # sum of basic tax
    sumD = Decimal("0")   # sum of 'distance' tax

    with open(filename, "rb") as infil:
        for i in xrange(5000):
            datum = infil.read(8)
            if datum == '': break
            n, =  unpack('>Q', datum)

            calltype = n & 1
            r = rates[calltype]

            p = Banker.quantize(r * n, twodig)

            b = p * basictax
            b = b.quantize(twodig)
            sumB += b

            t = p + b

            if calltype:
                d = p * disttax
                d = d.quantize(twodig)
                sumD += d
                t += d

            sumT += t

    infil.close()
    end = time()
    return end - start

def main(n):
    run() # warmup
    times = []
    for i in xrange(n):
        times.append(run())
    return times



if __name__ == "__main__":
    import optparse
    import util
    parser = optparse.OptionParser(
        usage="%prog [options]",
        description="Test the performance of the Telco decimal benchmark")
    util.add_standard_options_to(parser)
    options, args = parser.parse_args()

    util.run_benchmark(options, options.num_runs, main)
