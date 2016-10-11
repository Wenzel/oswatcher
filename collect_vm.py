#!/usr/bin/env python3

"""
Usage: collect_vm.py <vm_name>

Options:
    -h --help               Display this message
"""


# sys
import os
import sys
import re
import subprocess
import tempfile
import logging
import shutil
import xml.etree.ElementTree as ET
from collections import deque

# 3rd
from docopt import docopt
import libvirt
import guestfs
from sqlalchemy import insert

# local
# import db
from db import OSWatcherDB

__SCRIPT_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))

class VM:

    def __init__(self, vm_name):
        # connect to QEMU
        logging.info('Connecting to qemu:///session')
        self.con = libvirt.open('qemu:///session')
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

        self.db = OSWatcherDB(vm_name)

        # init variables
        self.counter = 0
        self.total_entries = 0

    def capture_filesystem(self):
        self.walk_count('/')
        self.walk_capture('/')
        # db.session.commit()


    def walk_count(self, node):
        self.total_entries += 1
        print("Enumerating entries ... [{}]".format(self.total_entries), end='\r')
        if self.g.is_dir(node):
            entries = self.g.ls(node)
            for entry in entries:
                abs_path = node + '/' + entry
                abs_path = abs_path.replace('//', '/')
                self.walk_count(abs_path)

    def walk_capture(self, node):
        self.counter += 1
        perc = round(self.counter * 100 / self.total_entries, 1)
        logging.info("[{} %] {}".format(perc, node))
        self.db.capture(node)
        if self.g.is_dir(node):
            entries = self.g.ls(node)
            for entry in entries:
                abs_path = node + '/' + entry
                abs_path = abs_path.replace('//', '/')
                self.walk_capture(abs_path)

    def capture(self, node):

def init_logger():
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

def main(args):
    init_logger()
    vm_name = args['<vm_name>']
    vm = VM(vm_name)
    vm.capture_filesystem()


if __name__ == '__main__':
    main(docopt(__doc__))
