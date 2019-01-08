#!/usr/bin/env python3

"""
Usage: capture.py [options] <vm_name> <plugins_configuration>

Options:
    -h --help                       Display this message
    -d --debug                      Enable debug output
    -c --connection=<URI>           Specify a libvirt URI [Default: qemu:///session]
"""


import sys

from docopt import docopt

from .capture import main


args = docopt(__doc__)
retcode = main(args)
sys.exit(retcode)
