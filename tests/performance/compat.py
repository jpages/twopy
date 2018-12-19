"""Compatibility stuff (especially for 2.x - 3.x bridging)"""

import sys
import functools
import itertools
try:
    from io import StringIO
except ImportError:
    from cStringIO import StringIO

if sys.version_info < (3,):
    int_types = (int, long)
    bytes = str
    unicode = unicode
    xrange = xrange
    long = long
    maxint = sys.maxint
    reduce = reduce
    imap = itertools.imap
    izip = itertools.izip
    def u_lit(s):
        r"""Make an unicode string from a regular string literal,
        intepreting \uXXXX escapes"""
        return eval('u"""' + s + '"""')
    def print_(*args, **kargs):
        sep = kargs.pop('sep', ' ')
        end = kargs.pop('end', '\n')
        file = kargs.pop('file', sys.stdout)
        if kargs:
            raise TypeError("unexpected keyword arguments %r" % (list(kargs),))
        file.write(sep.join(map(str, args)) + end)
    def next(x):
        return x.next()
else:
    import builtins
    int_types = (int,)
    bytes = bytes
    unicode = str
    xrange = range
    long = int
    maxint = sys.maxsize  # good enough
    reduce = functools.reduce
    imap = map
    izip = zip
    def u_lit(s):
        return s
    # Avoid syntax errors under 2.5
    _builtin_print = getattr(builtins, 'print')
    def print_(*args, **kargs):
        _builtin_print(*args, **kargs)
    next = next


