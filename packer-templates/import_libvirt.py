#!/usr/bin/env python3

"""
Usage:
    import_libvirt.py [options] <disk_image>

Options:
    -h --help                   Show this screen.
    -c --connection=<URI>       Specify a libvirt URI [Default: qemu:///session]
"""

import os
import sys
import logging
import shutil
from pathlib import Path
import xml.etree.ElementTree as tree

import libvirt
from docopt import docopt

PREFIX = 'oswatcher'
POOL_DIR_PATH_REL = '../images'
OSW_POOL_NAME = 'oswatcher'
PACKER_OUTPUT_DIR = 'output-qemu'
SNAPSHOT_XML = """
<domainsnapshot>
    <name>base</name>
</domainsnapshot>
"""

def prepare_domain_xml(domain_name, osw_image_path):
    with open('template_domain.xml') as templ:
        domain_xml = templ.read()
        domain_xml = domain_xml.format(domain_name, osw_image_path)
        root = tree.fromstring(domain_xml)
        domain_xml = tree.tostring(root).decode()
        return domain_xml
    return None

def main(args):
    logging.basicConfig(level=logging.DEBUG, format='%(message)s')
    qemu_image = args['<disk_image>']
    uri = args['--connection']
    con = libvirt.open(uri)
    script_dir = Path(__file__).parent
    storage_path = str(Path(script_dir / POOL_DIR_PATH_REL).resolve())
    # check for storage pool
    try:
        storage = con.storagePoolLookupByName(OSW_POOL_NAME)
    except libvirt.libvirtError:
        # build oswatcher pool xml
        path_elem = tree.Element('path')
        path_elem.text = storage_path
        target_elem = tree.Element('target')
        target_elem.append(path_elem)
        name_elem = tree.Element('name')
        name_elem.text = OSW_POOL_NAME
        pool_elem = tree.Element('pool', attrib={'type': 'dir'})
        pool_elem.append(name_elem)
        pool_elem.append(target_elem)
        pool_xml = tree.tostring(pool_elem).decode('utf-8')
        # define it
        storage = con.storagePoolDefineXML(pool_xml)
        storage.setAutostart(True)
    # create dir
    os.makedirs(storage_path, exist_ok=True)
    # make sure storage is running
    if not storage.isActive():
        storage.create()
    # check if domain is already defined
    image_name = os.path.basename(qemu_image)
    domain_name = '{}-{}'.format(PREFIX, image_name)
    try:
        domain = con.lookupByName(domain_name)
    except libvirt.libvirtError:
        # default system qemu
        qemu_bin_path = shutil.which('qemu-system-x86_64')
        # move image to oswatcher pool
        osw_image_path = os.path.join(storage_path, '{}.qcow2'.format(image_name))
        shutil.move(qemu_image, osw_image_path)
        domain_xml = prepare_domain_xml(domain_name, osw_image_path)
        con.defineXML(domain_xml)
        logging.info('Domain {} defined.'.format(domain_name))
        domain = con.lookupByName(domain_name)
        # take base snapshot
        domain.snapshotCreateXML(SNAPSHOT_XML)
        # remove output-qemu
        output_qemu_path = str(Path(script_dir / PACKER_OUTPUT_DIR))
        shutil.rmtree(output_qemu_path)
    else:
        logging.info('Domain {} already defined'.format(domain_name))



if __name__ == '__main__':
    args = docopt(__doc__)
    logging.basicConfig(level=logging.DEBUG)
    main(args)
