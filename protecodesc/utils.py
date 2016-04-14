# Copyright (c) 2015 Codenomicon Ltd.
# License: MIT

from __future__ import absolute_import, division, print_function

import datetime
import hashlib
import logging
import os
import os.path
import json
import requests
import sys

try:  # Python3
    from itertools import zip_longest, filterfalse
except ImportError:
    from itertools import izip_longest as zip_longest
    from itertools import ifilterfalse as filterfalse

logger = logging.getLogger(__name__)


class TimeoutHTTPAdapter(requests.adapters.HTTPAdapter):
    """HTTP Adapter with timeout support

    This is used so that every request doesn't have to explicitly set
    timeout value.
    """

    # Default timeout
    timeout = 10

    def send(self, request, timeout=None, **kwargs):
        if timeout is None:
            timeout = self.timeout
        return super(TimeoutHTTPAdapter, self).send(
            request, timeout=timeout, **kwargs)


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, datetime.date):
            return obj.isoformat()
        elif isinstance(obj, datetime.timedelta):
            return (datetime.datetime.min + obj).time().isoformat()
        else:
            return super(DateTimeEncoder, self).default(obj)


def file_sha1(fname):
    digest = hashlib.sha1()
    with open(fname, 'rb') as f:
        while True:
            block = f.read(2**10)  # 1kB
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def file_finder(paths):
    for path in paths:
        # Handle root in case individual file given
        if os.path.isfile(path):
            yield path
        for root, dirs, files in os.walk(path):
            for fname in files:
                fullpath = os.path.join(root, fname)
                file_is_file = os.path.isfile(fullpath)
                file_is_link = os.path.islink(fullpath)
                if file_is_file and not file_is_link:
                    yield fullpath


def clean_version(version_text):
    return version_text.strip().split(' ')[0]


def update_progress(current, total, msg=""):
    sys.stderr.write(("\r[{percentage:.1f}%] {current}/{total} {msg}\n"
                     .format(current=current, total=total,
                             percentage=float(current)/total*100,
                             msg=msg)))
    sys.stderr.flush()


def generator_reader(fd, block_size=8192):
    while True:
        data = fd.read(block_size)
        if not data:
            break
        yield data


def generator_progress(it, msg="Progress: {i:8d}"):
    """Write progress to stderr, pass through iterable"""
    for i, element in enumerate(it):
        sys.stderr.write("\r")
        sys.stderr.write(msg.format(i=i))
        yield element
    sys.stderr.write("\r\n")


def zip_directory(path, zip_file):
    """Zip directory contents recursively

    with zipfile.ZipFile('foo.zip', 'w') as zip_file:
        zip_directory('src/directory/', zip_file)
    """

    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            file_is_file = os.path.isfile(file_path)
            file_is_link = os.path.islink(file_path)
            if file_is_file and not file_is_link:
                zip_file.write(file_path)
            else:
                logger.debug('Ignored non-file {0}'.format(file_path))
