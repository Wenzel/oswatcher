#!/usr/bin/env python3

"""
Usage: script.py [options] <os>

Options:
    -h --help                       Display this message
    -d --debug                      Enable debug output
"""


import sys
import logging

from docopt import docopt
from py2neo import Graph
from graphviz import Digraph

from oswatcher.model import OS

DB_PASSWORD = "admin"

def walk_filesystem(inode, dot):
    logging.debug('%s: %s', inode.name, inode.mime_type)
    if inode.dyn_deps is not None:
        dot.node(inode.name)
        for dep in inode.dyn_deps.split(':'):
            logging.info('adding %s -> %s', inode.name, dep)
            dot.edge(inode.name, dep)
    for child in inode.children:
        walk_filesystem(child, dot)

def init_logger(debug=False):
    logging_level = logging.INFO
    if debug:
        logging_level = logging.DEBUG
    logging.basicConfig(level=logging_level)
    # suppress annoying log output
    logging.getLogger("httpstream").setLevel(logging.WARNING)
    logging.getLogger("neo4j.bolt").setLevel(logging.WARNING)


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

    dot = Digraph(comment='{} dependency graph'.format(os_name))
    walk_filesystem(root, dot)
    logging.info('rendering graph')
    dot.render('dependencies', view=False)

args = docopt(__doc__)
retcode = main(args)
sys.exit(retcode)
