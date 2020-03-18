

# sys
import os
import sys
import logging
import time
import json
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory, gettempdir

# local
from oswatcher.model import OS
from oswatcher.utils import get_hard_disk

# 3rd
import libvirt
from py2neo import Graph
from see import Environment
from see.context import QEMUContextFactory


__SCRIPT_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))
DB_PASSWORD = "admin"
DESKTOP_READY_DELAY = 180
SUBGRAPH_DELETE_OS = """
MATCH (o:OS)-[*0..]-(x)
WHERE o.name = "{}"
WITH DISTINCT x
DETACH DELETE x
"""


class QEMUDomainContextFactory(QEMUContextFactory):

    def __init__(self, domain_name, uri):
        # generate context.json and domain.xml
        self.domain_tmp_f = NamedTemporaryFile(mode='w')
        con = libvirt.open(uri)
        domain = con.lookupByName(domain_name)
        xml = domain.XMLDesc()
        self.domain_tmp_f.write(xml)
        self.domain_tmp_f.flush()
        # find domain qcow path
        qcow_path = Path(get_hard_disk(domain))
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
                    "provider": "see.image_providers.DummyProvider",
                    "provider_configuration": {
                        "path": qcow_path.parent,
                    },
                    "name": qcow_path.name,
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


def protocol(environment):
    context = environment.context
    config = environment.configuration['configuration']
    context.trigger('protocol_start')
    context.trigger('offline')
    desktop_ready_delay = config['desktop_ready_delay']
    if desktop_ready_delay > 0:
        # start domain
        logging.info("Starting the domain")
        context.poweron()
        # wait until desktop is ready
        logging.debug("Waiting %d seconds for desktop to be ready",
                      config['desktop_ready_delay'])
        time.sleep(config['desktop_ready_delay'])
        context.trigger('desktop_ready')
        # shutdown
        logging.info("Shutting down the domain")
        context.poweroff()
    context.trigger('protocol_end')


def init_logger(debug=False):
    formatter = "%(asctime)s %(levelname)s:%(name)s:%(message)s"
    logging_level = logging.INFO
    if debug:
        logging_level = logging.DEBUG
    logging.basicConfig(level=logging_level, format=formatter)
    # suppress annoying log output
    logging.getLogger("httpstream").setLevel(logging.WARNING)
    logging.getLogger("neo4j.bolt").setLevel(logging.WARNING)
    logging.getLogger("neobolt").setLevel(logging.WARNING)
    # silence GitPython debug output
    logging.getLogger("git").setLevel(logging.WARNING)
    logging.getLogger("git.cmd").setLevel(logging.WARNING)
    logging.getLogger("git.repo").setLevel(logging.WARNING)


def capture_main(args):
    vm_name = args['<vm_name>']
    uri = args['--connection']
    debug = args['--debug']
    hooks_config_path = args['<plugins_configuration>']

    init_logger(debug)

    # load hooks.json
    hooks_config = {}
    with open(hooks_config_path) as f:
        hooks_config = json.load(f)

    if 'configuration' not in hooks_config:
        hooks_config['configuration'] = {}

    # Neo4j required ?
    try:
        if hooks_config['configuration']['neo4j_db']:
            logging.info('Connect to Neo4j DB')
            graph = Graph(password=DB_PASSWORD)
            # insert graph object into general hook configuration
            hooks_config['configuration']['graph'] = graph
    except KeyError:
        # assume neo4j_db = false
        hooks_config['configuration']['neo4j_db'] = False

    # use default desktop ready delay if unset
    if "desktop_ready_delay" not in hooks_config['configuration']:
        hooks_config['configuration']['desktop_ready_delay'] = DESKTOP_READY_DELAY

    # insert vm_name object
    hooks_config['configuration']['domain_name'] = vm_name
    # insert debug flag
    hooks_config['configuration']['debug'] = debug

    # delete entire Neo4j graph ?
    try:
        delete = hooks_config['configuration']['delete']
    except KeyError:
        pass
    else:
        if delete and hooks_config['configuration']['neo4j_db']:
            logging.info("Deleting all nodes in graph database")
            graph.delete_all()
            # reset GraphQL IDL
            graph.run("CALL graphql.idl(null)")

    # replace existing OS in Neo4j ?
    if hooks_config['configuration']['neo4j_db']:
        os_match = OS.match(graph).where("_.name = '{}'".format(vm_name))
        try:
            replace = hooks_config['configuration']['replace']
        except KeyError:
            # assume replace = False
            if os_match.first():
                logging.info('OS already inserted, exiting')
                return
        else:
            if not replace and os_match.first():
                logging.info('OS already inserted, exiting')
                return
            elif os_match.first():
                # replace = True and an OS already exists
                logging.info('Deleting previous OS')
                graph.run(SUBGRAPH_DELETE_OS.format(vm_name))

    # Run the protocol
    with QEMUDomainContextFactory(vm_name, uri) as context:
        with Environment(context, hooks_config) as environment:
            logging.info('Capturing %s', vm_name)
            protocol(environment)
