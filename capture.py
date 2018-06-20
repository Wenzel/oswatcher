#!/usr/bin/env python3

"""
Usage: capture.py [options] <vm_name> <plugins_configuration>

Options:
    -h --help                       Display this message
    -c --connection=<URI>           Specify a libvirt URI [Default: qemu:///session]
"""


# sys
import os
import sys
import logging
import json
import time
import xml.etree.ElementTree as ET
from tempfile import NamedTemporaryFile
from contextlib import contextmanager

# 3rd
import libvirt
from docopt import docopt
from see import Environment
from see.context import QEMUContextFactory


__SCRIPT_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))


def protocol(context):
    context.trigger('init')
    context.poweron()
    time.sleep(30)
    context.poweroff()


def get_hard_disk(domain):
    root = ET.fromstring(domain.XMLDesc())
    disk = root.find("./devices/disk[@type='file'][@device='disk']")
    if disk is None:
        raise RuntimeError('Cannot find hard disk for domain {}'.format(domain.name()))
    qcow_path = disk.find('source').get('file')
    return qcow_path


@contextmanager
def generate_see_context(domain_name, uri):
    # generate context.json and domain.xml
    ctxt_tmp_f = NamedTemporaryFile(mode='w')
    domain_tmp_f = NamedTemporaryFile(mode='w')
    # find libvirt domain
    con = libvirt.open(uri)
    domain = con.lookupByName(domain_name)
    # write xml into temp file
    xml = domain.XMLDesc()
    domain_tmp_f.write(xml)
    domain_tmp_f.flush()
    # find domain qcow path
    qcow_path = get_hard_disk(domain)
    # storage path
    osw_storage_path = os.path.join(__SCRIPT_DIR, 'instances')

    context_config = {
        "hypervisor": uri,
        "domain": {
            "configuration": domain_tmp_f.name
        },
        "disk": {
            "image": {
                "uri": qcow_path,
                "provider": "see.image_providers.DummyProvider"
            },
            "clone": {
                "storage_pool_path": osw_storage_path,
                "copy_on_write": True
            }
        }
    }
    json.dump(context_config, ctxt_tmp_f)
    ctxt_tmp_f.flush()
    yield ctxt_tmp_f.name
    domain_tmp_f.close()
    ctxt_tmp_f.close()


def init_logger():
    logging.getLogger().setLevel(logging.DEBUG)
    # suppress annoying log output
    logging.getLogger("httpstream").setLevel(logging.WARNING)
    logging.getLogger("neo4j.bolt").setLevel(logging.WARNING)


def main(vm_name, uri, plugins_config):
    init_logger()

    with generate_see_context(vm_name, uri) as context_path:
        context = QEMUContextFactory(context_path)
        with Environment(context, plugins_config) as environment:
            protocol(environment.context)


if __name__ == '__main__':
    args = docopt(__doc__)
    vm_name = args['<vm_name>']
    uri = args['--connection']
    plugins_config = args['<plugins_configuration>']
    main(vm_name, uri, plugins_config)
