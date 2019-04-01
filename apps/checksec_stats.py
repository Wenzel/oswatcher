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

from oswatcher.model import OS

DB_PASSWORD = "admin"


def walk_filesystem(inode):
    c = Counter()
    if inode.checksec:
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

    for child in inode.children:
        c += walk_filesystem(child)
    return c

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
    root = list(os.root_fileystem)[0]
    counter = walk_filesystem(root)
    logging.info('Results for %s', os_name)
    logging.info('Total binaries: %d', counter['total'])
    for feature in ['relro', 'canary', 'nx', 'rpath', 'runpath', 'symtables', 'fortify_source']:
        logging.info('%s: %.1f%%', feature, counter[feature] * 100 / counter['total'])


args = docopt(__doc__)
retcode = main(args)
sys.exit(retcode)
