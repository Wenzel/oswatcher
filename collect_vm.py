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
    logging.debug('setting source = {}'.format(MYISO))
    try:
        # set
        cdrom.find('source').set('file', MYISO)
    except:
        # insert
        ET.SubElement(cdrom, 'source', {'file': MYISO})
    # boot from cdrom
    os = root.find('./os')
    try:
        # set
        os.find('boot').set('dev', 'cdrom')
    except:
        # insert
        ET.SubElement(os, 'boot', {'dev': 'cdrom'})

    # update VM
    with tempfile.NamedTemporaryFile() as tmp:
        new_xml = ET.tostring(root)
        tmp.write(new_xml)
        tmp.flush()
        args = ['define', tmp.name]
        run('virsh', args)
    # update cdrom source
    # set as bootable
    # set shared host dir
    # shared_dir = '''    
    # <filesystem type='mount' accessmode='passthrough'>
    #     <source dir='/tmp/testmount'/>
    #     <target dir='kvmshared'/>
    # </filesystem>
    # '''
    # try:
    #     vm.attachDeviceFlags(shared_dir)
    # except:
    #     pass # already exists

if __name__ == '__main__':
    main(docopt(__doc__))
