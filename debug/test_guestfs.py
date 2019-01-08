#!/usr/bin/env python3

"""
Usage: test_guestfs.py <qcow_path>

Options:
    -h --help                       Display this message
"""

# std
import logging
import sys
from docopt import docopt

# 3rd
import guestfs
from IPython import embed


def main(args):
    logging.getLogger().setLevel(logging.INFO)
    qcow_path = args['<qcow_path>']

    # init libguestfs
    g = guestfs.GuestFS(python_return_dict=True)
    # attach drive
    g.add_drive_opts(qcow_path, readonly=1)
    # run libguestfs backend
    logging.info('Running libguestfs')
    g.launch()
    # inspect operating system
    roots = g.inspect_os()
    if len(roots) == 0:
        logging.info('No operating system found !')
        sys.exit(1)

    # we should have one main filesystem
    root = roots[0]
    mps = g.inspect_get_mountpoints(root)
    # mount filesystem
    logging.info('Mounting main filesystem')
    for mount_point, device in mps.items():
        g.mount_ro(device, mount_point)

    # run IPython shell
    embed()


if __name__ == '__main__':
    main(docopt(__doc__))
