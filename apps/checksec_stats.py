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

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from docopt import docopt
from py2neo import Graph

from oswatcher.model import OS

DB_PASSWORD = "admin"
PROTECTIONS = ['relro', 'canary', 'nx', 'rpath', 'runpath', 'symtables', 'fortify_source']

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
    os =  OS.match(graph).where("_.name = '{}'".format(os_name)).first()
    if os is None:
        logging.info('unable to find OS %s in the database', os_name)
        logging.info('available operating systems:')
        for os in OS.match(graph):
            logging.info('⭢ %s', os.name)
        return 1

    # TODO translate to py2neo API
    checksec_inodes = graph.run("MATCH (os:OS)-[:OWNS_FILESYSTEM]->(root:Inode)-[:HAS_CHILD*]->(i:Inode) WHERE os.name = 'ubuntu16.04' AND i.checksec = True return i")
    c = Counter()
    for node in checksec_inodes:
        inode = node['i']
        logging.debug('%s: %s', inode['name'], inode['mime_type'])
        c['total'] += 1
        if inode['relro']:
            c['relro'] += 1
        if inode['canary']:
            c['canary'] += 1
        if inode['nx']:
            c['nx'] += 1
        if inode['rpath']:
            c['rpath'] += 1
        if inode['runpath']:
            c['runpath'] += 1
        if inode['symtables']:
            c['symtables'] += 1
        if inode['fortify_source']:
            c['fortify_source'] += 1

    logging.info('Results for %s', os.name)
    logging.info('Total binaries: %d', c['total'])
    for feature in PROTECTIONS:
        logging.info('%s: %.1f%%', feature, c[feature] * 100 / c['total'])

    sns.set_style('whitegrid')

    per_data = []
    for feature in PROTECTIONS:
        value = c[feature] * 100 / c['total']
        per_data.append(value)
    # initialize list of lists
    df = pd.DataFrame({'Protections': PROTECTIONS, 'Percentage': per_data})
    ax = sns.barplot(x="Protections", y="Percentage", data=df)
    ax.set_title('{} binary security'.format(os.name))
    # show plot
    plt.show()

if __name__ == '__main__':
    args = docopt(__doc__)
    retcode = main(args)
    sys.exit(retcode)
