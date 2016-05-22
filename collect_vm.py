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
import db

__SCRIPT_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))

class VM:

    def __init__(self, vm_name):
        # connect to QEMU
        self.con = libvirt.open('qemu:///session')
        if self.con == None:
            print('Failed to connect to Hypervisor !')
            sys.exit(1)
        # search vm
        vm = self.con.lookupByName(vm_name)
        # find qcow path
        root = ET.fromstring(vm.XMLDesc())
        disk = root.find("./devices/disk[@type='file'][@device='disk']")
        if disk is None:
            print('Cannot find VM main disk !')
            sys.exit(1)
        qcow_path = disk.find('source').get('file')
        # init libguestfs
        self.g = guestfs.GuestFS(python_return_dict=True)
        # attach drive
        self.g.add_drive_opts(qcow_path, readonly=1)
        # run libguestfs backend
        self.g.launch()
        # inspect operating system
        roots = self.g.inspect_os()
        if len(roots) == 0:
            print('No operating system found !')
            sys.exit(1)

        # we should have one main filesystem
        root = roots[0]
        mps = self.g.inspect_get_mountpoints (root)
        # mount filesystem
        for mount_point, device in mps.items():
            self.g.mount_ro(device, mount_point)

        # init variables
        self.cache_path_ids = []
        self.counter = 0
        self.total_entries = 0

    def capture_filesystem(self):
        self.walk_count('/')
        self.walk_capture('/')
        db.session.commit()


    def walk_count(self, node):
        self.total_entries += 1
        if self.g.is_dir(node):
            entries = self.g.ls(node)
            for entry in entries:
                abs_path = node + '/' + entry
                abs_path = abs_path.replace('//', '/')
                self.walk_count(abs_path)

    def walk_capture(self, node):
        self.capture(node)
        if self.g.is_dir(node):
            entries = self.g.ls(node)
            for entry in entries:
                abs_path = node + '/' + entry
                abs_path = abs_path.replace('//', '/')
                self.walk_capture(abs_path)

    def capture(self, node):
        self.counter += 1
        perc = round(self.counter * 100 / self.total_entries, 1)
        print(end="\033[K") # clear the line
        print("[{} %] {}".format(perc, node), end='\r')

        path_components = []
        # decompose path
        path = node
        while path != '/':
            # get up
            path = os.path.dirname(path)
            # insert new path component
            component = os.path.basename(path)
            # basename on '/' returns an empty string
            # we have to set it to the root entry manually
            if not component:
                component = '/'
            path_components.append(component)
         
        path_ids = []
        # ['c', 'b', 'a'] => ['a', 'b', 'c']
        path_components.reverse()
        # print(path_components)
        # print(self.cache_path_ids)
        # found each parent dir
        for i, component in enumerate(path_components):
            # try cache
            try:
                cache_entry = self.cache_path_ids[i]
                component_id = cache_entry[1]
                # tuple ("dir", id)
                if cache_entry[0] == component:
                    # print('found {} in cache'.format(component))
                    # we found an id in the cache !
                    path_ids.append(component_id)
                else:
                    # print('invalidate cache')
                    # delete element starting from index i to the end
                    del self.cache_path_ids[i:]
                    # query for ID
                    fs_obj = db.session.query(db.Filesystem).filter(db.Filesystem.name == component, db.Filesystem.path.contains(path_ids)).all()[0]
                    # append id to path_ids
                    path_ids.append(fs_obj.id)
                    # append new cache entry
                    cache_entry = (component, fs_obj.id)
                    self.cache_path_ids.append(cache_entry)

            except IndexError:
                # print("IndexError {}, outside of cache".format(i))
                # query for ID
                fs_obj = db.session.query(db.Filesystem).filter(db.Filesystem.name == component, db.Filesystem.path.contains(path_ids)).all()[0]
                # append id to path_ids
                path_ids.append(fs_obj.id)
                # append new cache entry
                cache_entry = (component, fs_obj.id)
                self.cache_path_ids.append(cache_entry)

        # root ?
        name = os.path.basename(node)
        if name == '':
            name = '/'
        trans = insert(db.Filesystem)
        trans.execute(path=path_ids, name=name)

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
