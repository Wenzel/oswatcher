#!/usr/bin/env python3

"""
Usage: script.py [options] <start> <end>

Options:
    -h --help                       Display this message
    -d --debug                      Enable debug output
    -f --flavor=FLAVOR              Specify Ubuntu flavor (server, desktop...) [Default: server]
    -a --arch=ARCH                  Specify architecture (i386, amd64...) [Default: amd64]
    -c --cpus=CPUS                  Specify the number of cpus to use for QEMU [Default: 2]
"""


import logging
import re
import json
import subprocess
import shutil
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from datetime import datetime

import requests
from docopt import docopt

UBUNTU_FIRST_RELEASE_MAJOR = 4
UBUNTU_FIRST_RELEASE_MINOR = 10
UBUNTU_OLD_RELEASE_URL = 'http://old-releases.ubuntu.com/releases'
UBUNTU_RELEASE_URL = 'http://releases.ubuntu.com'


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
        url += '.0'
        if valid_url is None and is_url_up(url):
            valid_url = url
        # recent release ?
        url = UBUNTU_RELEASE_URL + '/' + release_str
        if valid_url is None and is_url_up(url):
            valid_url = url
        # test append .0
        url += '.0'
        if valid_url is None and is_url_up(url):
            valid_url = url

        if valid_url is None:
            logging.warning('Unable to generate valid URL for %s', release_str)
        else:
            yield (release_str, valid_url)


def init_logger(debug=False):
    logging_level = logging.INFO
    if debug:
        logging_level = logging.DEBUG
    logging.basicConfig(level=logging_level)
    logging.getLogger('urllib3').setLevel(logging.WARNING)


def main(args):
    debug = args['--debug']
    init_logger(debug)
    start = args['<start>']
    end = args['<end>']
    flavor = args['--flavor']
    arch = args['--arch']
    cpus = args['--cpus']
    # validate args
    for release_nb in [start, end]:
        if not re.match(r'\d+\.\d+', release_nb):
            raise RuntimeError('argument invalid. must be a release number (like 14.04), got %s', release_nb)
    build_dir = Path(__file__).absolute().parent / 'build_output'
    logging.info('Creating build directory: %s', str(build_dir))
    os.makedirs(str(build_dir), exist_ok=True)
    for version, dir_url in gen_dir_urls(start, end):
        logging.info('Building Ubuntu %s', version)
        logging.debug('URL : %s', dir_url)
        with NamedTemporaryFile(mode='w') as tmp_varfile:
            varfile = {
                'vm_name': 'ubuntu-{}-{}-{}.qcow2'.format(version, flavor, arch),
                'memory': '512',
                'cpus': str(cpus),
                'disk_size': '65536',
                'iso_checksum_url': '{}/SHA1SUMS'.format(dir_url),
                'iso_checksum_type': 'sha1',
                'iso_url': '{}/ubuntu-{}-{}-{}.iso'.format(dir_url, version, flavor, arch),
                'preseed': 'ubuntu/preseed.cfg',
                'version': '1'
            }
            json.dump(varfile, tmp_varfile)
            tmp_varfile.flush()
            # build
            template = Path(__file__).resolve().parent / 'ubuntu.json'
            cmdline = ['packer', 'build', '-var-file', tmp_varfile.name, str(template)]
            output_qemu = Path(__file__).resolve().parent / 'output-qemu'
            try:
                logging.debug('Running: %s', cmdline)
                stdout = subprocess.DEVNULL
                if debug:
                    stdout = None
                subprocess.run(cmdline, check=True, stdout=stdout)
            except subprocess.CalledProcessError:
                logging.error('Packer build failed !')
            else:
                logging.info('build artifact %s', varfile['vm_name'])
                src = output_qemu / varfile['vm_name']
                dst = build_dir / varfile['vm_name']
                # move build artifact
                shutil.move(str(src), str(dst))
            finally:
                # ensure output-qemu is removed for next build
                shutil.rmtree(str(output_qemu), ignore_errors=True)

if __name__ == '__main__':
    args = docopt(__doc__)
    main(args)
