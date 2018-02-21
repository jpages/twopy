#!/usr/bin/env python

"""Wrapper script for testing the performance of the Mako template system."""

# Python imports
import optparse
import time

# Local imports
import util
from compat import xrange

# Mako imports
from mako.template import Template


MAKO_TMPL = Template("""<table>
% for row in table:
<tr>
    % for col in row:
        <td> ${col | h} </td>
    % endfor
</tr>
% endfor
</table>
""")

def test_mako(count):
    table = [xrange(150) for _ in xrange(150)]

    # Warm up Mako.
    MAKO_TMPL.render(table = table)
    MAKO_TMPL.render(table = table)

    times = []
    for _ in xrange(count):
        t0 = time.time()
        MAKO_TMPL.render(table = table)
        t1 = time.time()
        times.append(t1 - t0)
    return times


if __name__ == "__main__":
    parser = optparse.OptionParser(
        usage="%prog [options]",
        description=("Test the performance of Mako templates."))
    util.add_standard_options_to(parser)
    options, args = parser.parse_args()

    util.run_benchmark(options, options.num_runs, test_mako)
