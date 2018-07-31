#!/usr/bin/env python3

"""
Usage:
    import_libvirt.py [options] <disk_image>

Options:
    -h --help                   Show this screen.
    -d --debug                  Enable debug output
    -c --connection=<URI>       Specify a libvirt URI [Default: qemu:///session]
    -p --pool-name=<POOL>       Specify pool name [Default: oswatcher]
    -n --vm-name=<NAME>         Specify vm name
"""

import logging
import shutil
from pathlib import Path
import xml.etree.ElementTree as tree

import libvirt
from docopt import docopt

SCRIPT_DIR = Path(__file__).absolute().parent
PREFIX = 'osw'
POOL_DIR_PATH_REL = '../images'
PACKER_OUTPUT_DIR = 'output-qemu'
POOL_PATH = Path(SCRIPT_DIR / POOL_DIR_PATH_REL).resolve()


def prepare_domain_xml(vm_name, osw_image_path):
    with open('template_domain.xml') as templ:
        domain_xml = templ.read()
        domain_xml = domain_xml.format(vm_name, osw_image_path)
        root = tree.fromstring(domain_xml)
        domain_xml = tree.tostring(root).decode()
        return domain_xml


def setup_storage_pool(con, pool_name, pool_path):
    # check for storage pool
    try:
        pool = con.storagePoolLookupByName(pool_name)
    except libvirt.libvirtError:
        # build oswatcher pool xml
        path_elem = tree.Element('path')
        path_elem.text = str(pool_path)
        target_elem = tree.Element('target')
        target_elem.append(path_elem)
        name_elem = tree.Element('name')
        name_elem.text = pool_name
        pool_elem = tree.Element('pool', attrib={'type': 'dir'})
        pool_elem.append(name_elem)
        pool_elem.append(target_elem)
        pool_xml = tree.tostring(pool_elem).decode('utf-8')
        # define
        logging.info('Defining storage pool %s', pool_name)
        pool = con.storagePoolDefineXML(pool_xml)
        pool.setAutostart(True)
    else:
        logging.info('Storage pool %s already existing', pool_name)

    if not pool.isActive():
        pool.build()
        pool.create()
    return pool

def append_qcow(disk_image):
    if not disk_image.suffix == '.qcow2':
        return Path(str(disk_image) + '.qcow2')
    return disk_image

def setup_domain(con, vm_name, pool, disk_image, pool_path):
    # check if domain is already defined
    domain_name = '{}-{}'.format(PREFIX, disk_image.stem)
    if not vm_name:
        vm_name = domain_name
    try:
        domain = con.lookupByName(vm_name)
    except libvirt.libvirtError:
        disk_image = append_qcow(disk_image)
        # move image to oswatcher pool
        osw_image_path = pool_path / disk_image.name
        shutil.move(str(disk_image), str(osw_image_path))
        domain_xml = prepare_domain_xml(vm_name, osw_image_path)
        con.defineXML(domain_xml)
        logging.info('Domain %s defined.', vm_name)
        domain = con.lookupByName(vm_name)
        # refresh storage pool
        pool.refresh()
    else:
        logging.info('Domain %s already defined', vm_name)
    return domain

def main(args):
    debug = args['--debug']
    log_level = logging.INFO
    if debug:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level, format='%(message)s')

    disk_image = Path(args['<disk_image>']).absolute()
    pool_name = args['--pool-name']
    vm_name = args['--vm-name']
    uri = args['--connection']
    con = libvirt.open(uri)

    pool = setup_storage_pool(con, pool_name, POOL_PATH)
    setup_domain(con, vm_name, pool, disk_image, POOL_PATH)
    # remove output-qemu
    logging.info('Removing output-qemu')
    output_qemu_path = Path(SCRIPT_DIR / PACKER_OUTPUT_DIR)
    shutil.rmtree(str(output_qemu_path))


if __name__ == '__main__':
    args = docopt(__doc__)
    logging.basicConfig(level=logging.DEBUG)
    main(args)
