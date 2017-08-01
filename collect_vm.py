#!/usr/bin/env python3

"""
Usage: collect_vm.py [options] <vm_name>

Options:
    -h --help                       Display this message
    -c --connection=<URI>           Specify a libvirt URI [Default: qemu:///session]
"""


# sys
import os
import sys
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

# 3rd
from docopt import docopt
from py2neo import Graph
from model import Inode
import libvirt
import guestfs

__SCRIPT_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))
DB_PASSWORD = "admin"


class VM:

    def __init__(self, vm_name, uri):
        print(uri)
        # connect to QEMU
        logging.info('Connecting to {}'.format(uri))
        self.con = libvirt.open(uri)
        if self.con == None:
            logging.info('Failed to connect to Hypervisor !')
            sys.exit(1)
        # search vm
        logging.info('Searching VM')
        vm = self.con.lookupByName(vm_name)
        # find qcow path
        logging.info('Finding hard disk')
        root = ET.fromstring(vm.XMLDesc())
        disk = root.find("./devices/disk[@type='file'][@device='disk']")
        if disk is None:
            logging.info('Cannot find VM main disk !')
            sys.exit(1)
        qcow_path = disk.find('source').get('file')
        logging.info(qcow_path)
        # init libguestfs
        self.g = guestfs.GuestFS(python_return_dict=True)
        # attach drive
        self.g.add_drive_opts(qcow_path, readonly=1)
        # run libguestfs backend
        logging.info('Running libguestfs')
        self.g.launch()
        # inspect operating system
        roots = self.g.inspect_os()
        if len(roots) == 0:
            logging.info('No operating system found !')
            sys.exit(1)

        # we should have one main filesystem
        root = roots[0]
        mps = self.g.inspect_get_mountpoints (root)
        # mount filesystem
        logging.info('Mounting main filesystem')
        for mount_point, device in mps.items():
            self.g.mount_ro(device, mount_point)

        self.graph = Graph(password=DB_PASSWORD)
        # debug, erase every node
        self.graph.delete_all()

        # init variables
        self.counter = 0
        self.total_entries = 0

    def capture_filesystem(self):
        root = Path('/')
        self.walk_count(root)
        self.walk_capture(root)



    def walk_count(self, node):
        self.total_entries += 1
        print("Enumerating entries ... [{}]".format(self.total_entries), end='\r')
        if self.g.is_dir(str(node)):
            entries = self.g.ls(str(node))
            for entry in entries:
                subnode_abs = node / entry
                self.walk_count(subnode_abs)

    def walk_capture(self, node):
        self.counter += 1
        perc = round(self.counter * 100 / self.total_entries, 1)
        logging.info("[{} %] {}".format(perc, node))
        inode = Inode(self.g, node)
        if self.g.is_dir(str(node)):
            entries = self.g.ls(str(node))
            for entry in entries:
                subnode_abs = node / entry
                child_inode = self.walk_capture(subnode_abs)
                inode.children.add(child_inode)

        self.graph.create(inode)
        return inode

def init_logger():
    logging.getLogger().setLevel(logging.INFO)
    # suppress annoying log output
    logging.getLogger("httpstream").setLevel(logging.WARNING)
    logging.getLogger("neo4j.bolt").setLevel(logging.WARNING)

def main(args):
    init_logger()
    vm_name = args['<vm_name>']
    uri = args['--connection']
    vm = VM(vm_name, uri)
    vm.capture_filesystem()


if __name__ == '__main__':
    main(docopt(__doc__))
