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

# 3rd
from docopt import docopt
import libvirt


__SCRIPT_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))
MYISO = os.path.join(__SCRIPT_DIR, 'live.iso')
HOST_SHARED = os.path.join(__SCRIPT_DIR, 'host_shared')

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
    # get xml and list devices
    xml = vm.XMLDesc()
    root = ET.fromstring(xml)
    # find cdrom
    cdrom = root.find("./devices/disk[@device='cdrom']")
    # -> source = 'myiso'
    logging.debug('Setting CDROM source to {}'.format(MYISO))
    try:
        # set
        cdrom.find('source').set('file', MYISO)
    except:
        # insert
        ET.SubElement(cdrom, 'source', {'file': MYISO})
    # boot from cdrom
    os = root.find('./os')
    logging.debug('Setting CDROM as main boot device')
    try:
        # set
        os.find('boot').set('dev', 'cdrom')
    except:
        # insert
        ET.SubElement(os, 'boot', {'dev': 'cdrom'})

    # set shared host dir
    logging.debug('Setting shared filesystem')
    devices = root.find("./devices")
    filesystem = root.find("./devices/filesystem")
    target = "host_shared"
    if filesystem:
        # delete it
        devices.remove(filesystem)
    # insert
    logging.debug('Inserting new device : filesystem')
    ET.SubElement(devices, 'filesystem', {})
    filesystem = root.find("./devices/filesystem")
    # set attributes
    logging.debug('Setting filesystem attributes')
    filesystem.set('type', 'mount')
    filesystem.set('accessmode', 'passthrough')
    ET.SubElement(filesystem, 'source', { 'dir' : HOST_SHARED }) 
    ET.SubElement(filesystem, 'target', { 'dir' : target }) 

    # update VM
    logging.debug('Updating VM definition...')
    with tempfile.NamedTemporaryFile() as tmp:
        new_xml = ET.tostring(root)
        tmp.write(new_xml)
        tmp.flush()
        args = ['define', tmp.name]
        run('virsh', args)

if __name__ == '__main__':
    main(docopt(__doc__))
