#!/usr/bin/python

"""Test the performance of simple HTTP serving and client using the Tornado
framework.

A trivial "application" is generated which generates a number of chunks of
data as a HTTP response's body.
"""

import optparse
import socket
import time

from compat import xrange
import util

from tornado.httpclient import AsyncHTTPClient
from tornado.httpserver import HTTPServer
from tornado.gen import coroutine, Task
from tornado.ioloop import IOLoop
from tornado.netutil import bind_sockets
from tornado.web import RequestHandler, Application


HOST = "127.0.0.1"
FAMILY = socket.AF_INET

CHUNK = b"Hello world\n" * 1000
NCHUNKS = 5

CONCURRENCY = 150


class MainHandler(RequestHandler):
    @coroutine
    def get(self):
        for i in range(NCHUNKS):
            self.write(CHUNK)
            yield Task(self.flush)

    def compute_etag(self):
        # Overriden to avoid stressing hashlib in this benchmark
        return None


def make_application():
    return Application([
        (r"/", MainHandler),
    ])


def make_http_server(loop, request_handler):
    server = HTTPServer(request_handler, io_loop=loop)
    sockets = bind_sockets(0, HOST, family=FAMILY)
    assert len(sockets) == 1
    server.add_sockets(sockets)
    return sockets[0].getsockname()


def test_tornado(count):
    loop = IOLoop.instance()
    host, port = make_http_server(loop, make_application())
    url = "http://%s:%s/" % (host, port)
    times = []

    @coroutine
    def main():
        client = AsyncHTTPClient()
        for i in xrange(count):
            t0 = time.time()
            futures = [client.fetch(url) for j in xrange(CONCURRENCY)]
            for fut in futures:
                resp = yield fut
                buf = resp.buffer
                buf.seek(0, 2)
                assert buf.tell() == len(CHUNK) * NCHUNKS
            t1 = time.time()
            times.append(t1 - t0)

    loop.run_sync(main)
    return times


if __name__ == "__main__":
    parser = optparse.OptionParser(
        usage="%prog [options]",
        description=("Test the performance of HTTP requests with Tornado."))
    util.add_standard_options_to(parser)
    options, args = parser.parse_args()

    util.run_benchmark(options, options.num_runs, test_tornado)
