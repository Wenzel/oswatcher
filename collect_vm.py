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

def run(executable, args, working_dir=os.getcwd()):
    # find executable
    executable_full_path = shutil.which(executable)
    # add executable full path as argv[0]
    args.insert(0, executable_full_path)
    # run subprocess
    p = subprocess.Popen(args, executable=executable_full_path, cwd=working_dir)
    # get output
    (stdout, stderr) = p.communicate()
    return p.returncode

def init_logger():
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

def main(args):
    init_logger()
    # connect to QEMU
    con = libvirt.open('qemu:///session')
    if con == None:
        print('Failed to connect to Hypervisor !')
        sys.exit(1)
    # search vm
    vm_name = args['<vm_name>']
    vm = con.lookupByName(vm_name)
    # find qcow path
    root = ET.fromstring(vm.XMLDesc())
    disk = root.find("./devices/disk[@type='file'][@device='disk']")
    if disk is None:
        print('Cannot find VM main disk !')
        sys.exit(1)
    qcow_path = disk.find('source').get('file')
    print(qcow_path)
    # init libguestfs
    g = guestfs.GuestFS(python_return_dict=True)
    # attach drive
    g.add_drive_opts(qcow_path, readonly=1)
    # run libguestfs backend
    g.launch()
    # inspect operating system
    roots = g.inspect_os()
    if len(roots) == 0:
        print('No operating system found !')
        sys.exit(1)

    # we should have one main filesystem
    root = roots[0]
    mps = g.inspect_get_mountpoints (root)
    print(mps)
    # mount filesystem
    for mount_point, device in mps.items():
        g.mount_ro(device, mount_point)

    visit(g, '/')

def deep_walk_it(func):
    def wrapper(g, node):
        stack = []
        stack.append(node)
        while len(stack) != 0:
            node = stack.pop()
            func(g, node)
            if g.is_dir(node):
                entries = g.ls(node)
                for entry in entries:
                    abs_path = node + '/' + entry
                    abs_path = abs_path.replace('//', '/')
                    stack.append(abs_path)
    return wrapper

def width_walk_it(func):
    def wrapper(g, node):
        queue = deque()
        queue.append(node)
        while len(queue) != 0:
            node = queue.popleft()
            func(g, node)
            if g.is_dir(node):
                entries = g.ls(node)
                for entry in entries:
                    abs_path = node + '/' + entry
                    abs_path = abs_path.replace('//', '/')
                    queue.append(abs_path)
    return wrapper

def deep_walk_rec(func):
    def wrapper(g, node):
        func(g, node)
        if g.is_dir(node):
            entries = g.ls(node)
            for entry in entries:
                abs_path =  + '/' + entry
                abs_path = abs_path.replace('//', '/')
                wrapper(g, abs_path, parent)
                
    return wrapper

@deep_walk_it
def visit(g, node):
    print("Inserting {}".format(node))

    path_components = []
    entry = os.path.basename(node)
    # decompose path
    parent_id = 0
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
     
    print(path_components)
    # found each parent dir
    while len(path_components) > 0:
        # take next parent_dir
        parent_dir = path_components.pop()
        # query for ID
        fs_obj = db.session.query(db.Filesystem).filter_by(parent_id=parent_id, entry=parent_dir).all()[0]
        # update parent and last_dir
        parent_id = fs_obj.id
        # print("parent {} -> {}".format(parent_dir, parent_id))
    # root ?
    if entry == '':
        entry = '/'
    trans = insert(db.Filesystem)
    trans.execute(parent_id=parent_id, entry=entry)
    db.session.commit()

if __name__ == '__main__':
    main(docopt(__doc__))
