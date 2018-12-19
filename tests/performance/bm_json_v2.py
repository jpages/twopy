import time
import json

from compat import u_lit, xrange

# execution runtime per test case
TARGET_RUNTIME = 10

EMPTY = ({}, 200000)
SIMPLE_DATA = {'key1': 0, 'key2': True, 'key3': 'value', 'key4': 'foo',
               'key5': 'string'}
SIMPLE = (SIMPLE_DATA, 100000)
NESTED_DATA = {'key1': 0, 'key2': SIMPLE[0], 'key3': 'value', 'key4': SIMPLE[0],
               'key5': SIMPLE[0], u_lit('key'): u_lit('\u0105\u0107\u017c')}
NESTED = (NESTED_DATA, 100000)
HUGE = ([NESTED[0]] * 1000, 100)

cases = ['EMPTY', 'SIMPLE', 'NESTED', 'HUGE']

def main(n):
    l = []
    for i in xrange(n):
        t0 = time.time()
        for case in cases:
            data, count = globals()[case]
            for i in xrange(count):
                json.dumps(data)
        l.append(time.time() - t0)
    return l

if __name__ == '__main__':
    import util, optparse
    parser = optparse.OptionParser(
        usage="%prog [options]",
        description="Test the performance of the JSON benchmark")
    util.add_standard_options_to(parser)
    options, args = parser.parse_args()

    util.run_benchmark(options, options.num_runs, main)
