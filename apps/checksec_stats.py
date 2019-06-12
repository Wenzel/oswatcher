#!/usr/bin/env python3

"""
Usage:
    script.py --list
    script.py [options] <os_regex>

Options:
    -h --help                       Display this message
    -l --list                       List available OS in the database
    -d --debug                      Enable debug output
"""


import sys
import logging
from datetime import datetime
from collections import Counter

import matplotlib
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from docopt import docopt
from py2neo import Graph

from oswatcher.model import OS

DB_PASSWORD = "admin"
PROTECTIONS = ['relro', 'canary', 'nx', 'fortify_source', 'rpath', 'runpath', 'symtables']
OS_CHECKSEC_QUERY = """
MATCH (os:OS)-[:OWNS_FILESYSTEM]->(root:Inode)-[:HAS_CHILD*]->(i:Inode)
WHERE os.name = '{}' AND i.checksec = True
RETURN i
"""

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

    # list ?
    if args['--list']:
        logging.info('available operating systems:')
        for os in OS.match(graph):
            logging.info('\t%s', os.name)
        return

    os_regex = args['<os_regex>']
    os_match = OS.match(graph).where("_.name =~ '{}'".format(os_regex))
    if os_match is None:
        logging.info('unable to find OS that matches \'%s\' regex in the database', os_regex)
        return 1

    os_df_list = []
    # iterate over OS list, sorted by release date, converted from string to date object
    for os in sorted(os_match, key=lambda x: datetime.strptime(x.release_date, '%Y-%m-%d')):
        # TODO translate to py2neo API
        checksec_inodes = graph.run(OS_CHECKSEC_QUERY.format(os.name))
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

        # fix matplotlib, uses agg by default, non-gui backend
        matplotlib.use('tkagg')
        sns.set_style('whitegrid')

        per_data = []
        for feature in PROTECTIONS:
            value = c[feature] * 100 / c['total']
            per_data.append(value)
        # initialize OS Panda DataFrame
        df = pd.DataFrame({'Protections': PROTECTIONS, 'Percentage': per_data, 'OS': os.name})
        os_df_list.append(df)

    # concatenate all the individual DataFrames
    main_df = pd.concat(os_df_list, ignore_index=True)

    logging.info('Displaying results...')
    if len(os_df_list) == 1:
        ax = sns.barplot(x="Protections", y="Percentage", data=main_df)
        ax.set_title('{} binary security overview'.format(os_regex))
    else:
        ax = sns.barplot(x="Protections", y="Percentage", hue="OS", data=main_df)
        ax.set_title('binary security overview for regex "{}"'.format(os_regex))
    # show plot
    plt.legend(loc='upper right')
    plt.show()


if __name__ == '__main__':
    args = docopt(__doc__)
    retcode = main(args)
    sys.exit(retcode)
