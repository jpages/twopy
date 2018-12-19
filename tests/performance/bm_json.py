#!/usr/bin/env python

"""Script for testing the performance of json parsing and serialization.

This will dump/load several real world-representative objects a few
thousand times. The methodology below was chosen for was chosen to be similar
to real-world scenarios which operate on single objects at a time.
"""

from __future__ import division

# Python imports
import datetime
import optparse
import random
import sys
import time

# Local imports
import util
from compat import (
    xrange, bytes, unicode, int_types, long, maxint)


DICT = {
    'ads_flags': 0,
    'age': 18,
    'bulletin_count': 0,
    'comment_count': 0,
    'country': 'BR',
    'encrypted_id': 'G9urXXAJwjE',
    'favorite_count': 9,
    'first_name': '',
    'flags': 412317970704,
    'friend_count': 0,
    'gender': 'm',
    'gender_for_display': 'Male',
    'id': 302935349,
    'is_custom_profile_icon': 0,
    'last_name': '',
    'locale_preference': 'pt_BR',
    'member': 0,
    'tags': ['a', 'b', 'c', 'd', 'e', 'f', 'g'],
    'profile_foo_id': 827119638,
    'secure_encrypted_id': 'Z_xxx2dYx3t4YAdnmfgyKw',
    'session_number': 2,
    'signup_id': '201-19225-223',
    'status': 'A',
    'theme': 1,
    'time_created': 1225237014,
    'time_updated': 1233134493,
    'unread_message_count': 0,
    'user_group': '0',
    'username': 'collinwinter',
    'play_count': 9,
    'view_count': 7,
    'zip': ''}

TUPLE = (
    [265867233, 265868503, 265252341, 265243910, 265879514,
     266219766, 266021701, 265843726, 265592821, 265246784,
     265853180, 45526486, 265463699, 265848143, 265863062,
     265392591, 265877490, 265823665, 265828884, 265753032], 60)


def mutate_dict(orig_dict, random_source):
    new_dict = dict(orig_dict)
    for key, value in new_dict.items():
        rand_val = random_source.random() * maxint
        if isinstance(key, int_types + (bytes, unicode)):
            new_dict[key] = type(key)(rand_val)
    return new_dict


random_source = random.Random(5)  # Fixed seed.
DICT_GROUP = [mutate_dict(DICT, random_source) for _ in range(3)]


def test_json_dump(num_obj_copies, json, options):
    # Warm-up runs.
    json.dumps(DICT)
    json.dumps(TUPLE)
    json.dumps(DICT_GROUP)

    loops = num_obj_copies // 20  # We do 20 runs per loop.
    times = []
    for _ in xrange(options.num_runs):
        t0 = time.time()
        for _ in xrange(loops):
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(DICT)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(TUPLE)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
            json.dumps(DICT_GROUP)
        t1 = time.time()
        times.append(t1 - t0)
    return times


def test_json_load(num_obj_copies, json, options):
    json_dict = json.dumps(DICT)
    json_tuple = json.dumps(TUPLE)
    json_dict_group = json.dumps(DICT_GROUP)

    # Warm-up runs.
    json.loads(json_dict)
    json.loads(json_tuple)
    json.loads(json_dict_group)

    loops = num_obj_copies // 20  # We do 20 runs per loop.
    times = []
    for _ in xrange(options.num_runs):
        t0 = time.time()
        for _ in xrange(loops):
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_dict)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_tuple)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
            json.loads(json_dict_group)
        t1 = time.time()
        times.append(t1 - t0)
    return times


if __name__ == "__main__":
    parser = optparse.OptionParser(
        usage="%prog [json_dump|json_load] [options]",
        description=("Test the performance of JSON (de)serializing."))
    util.add_standard_options_to(parser)
    options, args = parser.parse_args()

    benchmarks = ["json_dump", "json_load"]
    for bench_name in benchmarks:
        if bench_name in args:
            benchmark = globals()["test_" + bench_name]
            break
    else:
        raise RuntimeError("Need to specify one of %s" % benchmarks)

    num_obj_copies = 8000
    import json

    util.run_benchmark(options, num_obj_copies, benchmark, json, options)
