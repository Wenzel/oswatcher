# sys
import logging
import json
import xml.etree.ElementTree as ET

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
        self.context.subscribe('neo4jfs_capture_end', self.add_filesystem)
        self.context.subscribe('syscalls_inserted', self.add_syscalls)
        self.context.subscribe('processes_inserted', self.add_processes)
        self.context.subscribe('protocol_end', self.insert_operating_system)

    def build_operating_system(self, event):
        xml = self.context.domain.XMLDesc()
        root = ET.fromstring(xml)
        # find description
        elems = root.findall('./description')
        release_date = None
        if elems:
            desc = elems[0]
            try:
                metadata = json.loads(desc.text)
            except json.JSONDecodeError:
                raise RuntimeError('Could not load JSON metadata')
            else:
                release_date = metadata['release_date']
                self.logger.info('OS release date: %s', release_date)
        self.os = OS(self.domain_name, release_date)

    def add_filesystem(self, event):
        logging.info('Adding root filesystem to OS node')
        root = event.root
        self.os.root_fileystem.add(root)
        root.owned_by.add(self.os)
        self.graph.push(root)

    def add_syscalls(self, event):
        logging.info('Adding syscalls to OS node')
        syscall_nodes = event.syscalls
        for syscall in syscall_nodes:
            self.os.syscalls.add(syscall)
            syscall.owned_by.add(self.os)
            self.graph.push(syscall)

    def add_processes(self, event):
        logging.info('Adding processes to OS node')
        processes = event.processes
        for p in processes:
            self.os.processes.add(p)
            p.owned_by.add(self.os)
            self.graph.push(p)

    def insert_operating_system(self, event):
        logging.info('Inserting OS node %s', self.domain_name)
        self.graph.push(self.os)
