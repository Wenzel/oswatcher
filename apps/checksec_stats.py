#!/usr/bin/env python3

"""
Usage: script.py [options] <os>

Options:
    -h --help                       Display this message
    -d --debug                      Enable debug output
"""


import sys
import logging
from collections import Counter

from docopt import docopt
from py2neo import Graph

from oswatcher.model import OS, Inode

DB_PASSWORD = "admin"


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
    init_logger(args['--debug'])
    logging.info('connect to Neo4j DB')
    graph = Graph(password=DB_PASSWORD)
    os_name = args['<os>']
    os = OS.match(graph).where("_.name = '{}'".format(os_name)).first()
    if os is None:
        logging.info('unable to find OS %s in the database', os_name)
        logging.info('available operating systems:')
        for os in OS.match(graph):
            logging.info('⭢ %s', os.name)
        return 1
    inode_checksec_list = Inode.match(graph).where(checksec=True)
    c = Counter()
    for inode in inode_checksec_list:
        logging.debug('%s: %s', inode.name, inode.mime_type)
        c['total'] += 1
        if inode.relro:
            c['relro'] += 1
        if inode.canary:
            c['canary'] += 1
        if inode.nx:
            c['nx'] += 1
        if inode.rpath:
            c['rpath'] += 1
        if inode.runpath:
            c['runpath'] += 1
        if inode.symtables:
            c['symtables'] += 1
        if inode.fortify_source:
            c['fortify_source'] += 1

    logging.info('Results for %s', os_name)
    logging.info('Total binaries: %d', c['total'])
    for feature in ['relro', 'canary', 'nx', 'rpath', 'runpath', 'symtables', 'fortify_source']:
        logging.info('%s: %.1f%%', feature, c[feature] * 100 / c['total'])

if __name__ == '__main__':
    args = docopt(__doc__)
    retcode = main(args)
    sys.exit(retcode)
