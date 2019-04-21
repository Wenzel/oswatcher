#!/usr/bin/env python3

"""
Usage: script.py [options] <start> <end>

Options:
    -h --help                       Display this message
    -d --debug                      Enable debug output
"""


import logging
import re
from datetime import datetime

import requests
from docopt import docopt

UBUNTU_FIRST_RELEASE_MAJOR = 4
UBUNTU_FIRST_RELEASE_MINOR = 10
UBUNTU_OLD_RELEASE_URL = 'http://old-releases.ubuntu.com/releases'
UBUNTU_RECENT_RELEASE_URL = 'http://releases.ubuntu.com'


def is_url_up(url):
    logging.debug('Checking for %s', url)
    return True if requests.get(url).status_code == 200 else False

def gen_ubuntu_releases(start, end):
    # gen list of all stable version of ubuntu
    # filter by start/end range
    m = re.match(r'(?P<major>\d+)\.(?P<minor>\d+)', start)
    start_major = int(m.group('major'))
    start_minor = int(m.group('minor'))
    m = re.match(r'(?P<major>\d+)\.(?P<minor>\d+)', end)
    end_major = int(m.group('major'))
    end_minor = int(m.group('minor'))
    today = datetime.today()
    major_cur = today.year % 2000
    # loop from 4.10 until today
    for major in range(4, major_cur+1):
        for minor in range(4, 10+1, 6):
            # Ubuntu releases started at 4.10
            if major == UBUNTU_FIRST_RELEASE_MAJOR and minor < UBUNTU_FIRST_RELEASE_MINOR:
                continue
            if major == major_cur:
                # .04/10 already released ?
                if today.month <= minor:
                    # not yet, continue
                    continue
            # filter by our ranges
            if major in range(start_major, end_major + 1):
                if major == start_major:
                    # check minor
                    if minor < start_minor:
                        continue
                elif major == end_major:
                    # check minor
                    if minor > end_minor:
                        continue
                yield (major, minor)

def gen_dir_urls(start, end):
    for major, minor in gen_ubuntu_releases(start, end):
        valid_url = None
        # try old-release first
        release_str = '{:d}.{:02d}'.format(major, minor)
        url = UBUNTU_OLD_RELEASE_URL + '/' + release_str
        if is_url_up(url):
            valid_url = url
        # sometimes you need a .0
        # like for 10.04.0
        url += '.0/'
        if is_url_up(url):
            valid_url = url
        # maybe it's a recent release
        url = UBUNTU_RECENT_RELEASE_URL + '/' + release_str
        if is_url_up(url):
            valid_url = url
        # try with a 0
        url += '.0/'
        if is_url_up(url):
            valid_url = url
        if valid_url is None:
            logging.warning('Unable to generate valid URL for %s', release_str)
        else:
            yield valid_url

def init_logger(debug=False):
    logging_level = logging.INFO
    if debug:
        logging_level = logging.DEBUG
    logging.basicConfig(level=logging_level)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

def main(args):
    print(args)
    init_logger(args['--debug'])
    start = args['<start>']
    end = args['<end>']
    # validate args
    for release_nb in [start, end]:
        if not re.match(r'\d+\.\d+', release_nb):
            raise RuntimeError('argument invalid. must be a release number (like 14.04), got %s', release_nb)
    for dir_url in gen_dir_urls(start, end):
        logging.info('URL : %s', dir_url)


if __name__ == '__main__':
    args = docopt(__doc__)
    main(args)
