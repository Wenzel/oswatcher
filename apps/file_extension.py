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
import matplotlib.pyplot as plt

from oswatcher.model import OS

DB_PASSWORD = "admin"


def walk_filesystem(inode):
    logging.debug('%s: %s', inode.name, inode.mime_type)
    c = Counter()
    if inode.mime_type is not None:
        c[inode.mime_type] += 1
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

    # display
    patches, texts, autotexts = plt.pie(counter.values(), labels=counter.keys(), autopct='%1.1f%%',
            shadow=False, startangle=90)
    plt.legend(fontsize='x-small', loc='center right')
    plt.axis('equal')
    plt.title('{}: MIME Types'.format(os.name))
    plt.show()


args = docopt(__doc__)
retcode = main(args)
sys.exit(retcode)
