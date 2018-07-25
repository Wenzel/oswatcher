#!/usr/bin/env python3

"""
Usage: capture.py [options] <vm_name> <plugins_configuration>

Options:
    -h --help                       Display this message
    -d --debug                      Enable debug output
    -c --connection=<URI>           Specify a libvirt URI [Default: qemu:///session]
"""


# sys
import os
import sys
import logging
import time
import json
from tempfile import NamedTemporaryFile, TemporaryDirectory, gettempdir

# local
from oswatcher.utils import get_hard_disk

# 3rd
import libvirt
from docopt import docopt
from py2neo import Graph
from see import Environment
from see.context import QEMUContextFactory


__SCRIPT_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))
DB_PASSWORD = "admin"
DESKTOP_READY_WAIT_TIME = 60


class QEMUDomainContextFactory(QEMUContextFactory):

    def __init__(self, domain_name, uri="qemu:///system"):
        # generate context.json and domain.xml
        self.domain_tmp_f = NamedTemporaryFile(mode='w')
        con = libvirt.open(uri)
        domain = con.lookupByName(domain_name)
        xml = domain.XMLDesc()
        self.domain_tmp_f.write(xml)
        self.domain_tmp_f.flush()
        # find domain qcow path
        qcow_path = get_hard_disk(domain)
        # storage path
        self.osw_storage_path = TemporaryDirectory(prefix="osw-instances-",
                                              dir=gettempdir())

        context_config = {
            "hypervisor": uri,
            "domain": {
                "configuration": self.domain_tmp_f.name
            },
            "disk": {
                "image": {
                    "uri": qcow_path,
                    "provider": "see.image_providers.DummyProvider"
                },
                "clone": {
                    "storage_pool_path": self.osw_storage_path.name,
                    "copy_on_write": True
                }
            }
        }
        super().__init__(context_config)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.osw_storage_path.cleanup()
        self.domain_tmp_f.close()


def protocol(context):
    context.trigger('protocol_start')
    context.trigger('offline')
    # start domain
    logging.info("Starting the domain")
    context.poweron()
    # wait until desktop is ready
    logging.debug("Waiting %d seconds for desktop to be ready", DESKTOP_READY_WAIT_TIME)
    time.sleep(DESKTOP_READY_WAIT_TIME)
    context.trigger('desktop_ready')
    # shutdown
    logging.info("Shutting down the domain")
    context.poweroff()
    context.trigger('protocol_end')


def init_logger(debug=False):
    logging_level = logging.INFO
    if debug:
        logging_level = logging.DEBUG
    logging.basicConfig(level=logging_level)
    # suppress annoying log output
    logging.getLogger("httpstream").setLevel(logging.WARNING)
    logging.getLogger("neo4j.bolt").setLevel(logging.WARNING)


def main(vm_name, uri, hooks_config_path, debug):
    init_logger(debug)

    hooks_config = {}
    with open(hooks_config_path) as f:
        hooks_config = json.load(f)
    logging.info('connect to Neo4j DB')
    graph = Graph(password=DB_PASSWORD)

    if not 'configuration' in hooks_config:
        hooks_config['configuration'] = {}
    # insert graph object into general hook configuration
    hooks_config['configuration']['graph'] = graph
    # insert vm_name object
    hooks_config['configuration']['domain_name'] = vm_name

    # delete entire graph ?
    if "delete" in hooks_config['configuration']:
        logging.info("Deleting all nodes in graph database")
        graph.delete_all()

    with QEMUDomainContextFactory(vm_name, uri) as context:
        with Environment(context, hooks_config) as environment:
            protocol(environment.context)


if __name__ == '__main__':
    args = docopt(__doc__)
    vm_name = args['<vm_name>']
    uri = args['--connection']
    debug = args['--debug']
    hooks_config_path = args['<plugins_configuration>']
    main(vm_name, uri, hooks_config_path, debug)
