#!/usr/bin/env python3

"""
Usage: capture_all.py [options] <regex> <plugins_configuration>

Options:
    -h --help                       Display this message
    -d --debug                      Enable debug output
    -c --connection=<URI>           Specify a libvirt URI [Default: qemu:///session]
"""

import sys
import logging
import libvirt
import subprocess
import re
from datetime import datetime
from pathlib import Path

from docopt import docopt


def init_logger(debug=False):
    logging_level = logging.INFO
    if debug:
        logging_level = logging.DEBUG
    logging.basicConfig(level=logging_level)
    # suppress annoying log output
    logging.getLogger("httpstream").setLevel(logging.WARNING)
    logging.getLogger("neo4j.bolt").setLevel(logging.WARNING)
    logging.getLogger("neobolt").setLevel(logging.WARNING)


def main(args):
    uri = args['--connection']
    debug = args['--debug']
    hooks_config_path = Path(args['<plugins_configuration>']).absolute()
    pattern = args['<regex>']

    init_logger(debug)
    parent_dir = Path(__file__).parent.parent
    logging.debug('connecting to %s', uri)
    con = libvirt.open(uri)
    for domain in con.listAllDomains():
        if re.match(pattern, domain.name()):
            cmdline = [sys.executable, '-m', 'oswatcher', domain.name(), str(hooks_config_path)]
            logging.info('#### BEGIN %s ####', domain.name())
            start = datetime.now()
            try:
                proc = subprocess.Popen(cmdline, cwd=str(parent_dir))
                proc.wait()
            except KeyboardInterrupt:
                logging.info('stopping capture !')
                break
            except subprocess.CalledProcessError:
                logging.fatal('Capturing domain %s failed', domain.name())
            elapsed = datetime.now() - start
            logging.info('Time elapsed: %s', str(elapsed).split('.')[0])
            logging.info('#### END %s ####', domain.name())


if __name__ == '__main__':
    args = docopt(__doc__)
    main(args)

