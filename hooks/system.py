# sys
import logging

# local
from oswatcher.model import OS

# 3rd
from see import Hook


class OperatingSystemHook(Hook):

    def __init__(self, parameters):
        super().__init__(parameters)
        self.os = None
        # config
        self.graph = self.configuration['graph']
        self.domain_name = self.configuration['domain_name']
        self.context.subscribe('protocol_start', self.build_operating_system)
        self.context.subscribe('filesystem_inserted', self.add_filesystem)
        self.context.subscribe('syscalls_inserted', self.add_syscalls)
        self.context.subscribe('protocol_end', self.insert_operating_system)

    def build_operating_system(self, event):
        self.os = OS(self.domain_name)

    def add_filesystem(self, event):
        logging.info('Adding root filesystem to OS node')
        root = event.root
        self.os.root_fileystem.add(root)

    def add_syscalls(self, event):
        logging.info('Adding syscalls to OS node')
        syscalls = event.syscalls
        [self.os.syscalls.add(s) for s in syscalls]

    def insert_operating_system(self, event):
        logging.info('Inserting OS node %s', self.domain_name)
        self.graph.create(self.os)
