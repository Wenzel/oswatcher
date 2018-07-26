# sys
import json
from io import StringIO

# local
from oswatcher.model import Process

# 3rd
from see import Hook
from rekall import plugins, session


class ProcessListHook(Hook):

    def __init__(self, parameters):
        super().__init__(parameters)
        # config
        self.graph = self.configuration['graph']
        self.context.subscribe('memory_dumped', self.extract_process_list)

    def extract_process_list(self, event):
        self.logger.info('Extracting the process list')
        memdump_path = event.memdump_path
        # build rekall session
        s = session.Session(
            filename=memdump_path,
            autodetect=["rsds"],
            logger=self.logger,
            autodetect_build_local='none',
            format='data',
            profile_path=[
                "http://profiles.rekall-forensic.com"
        ])

        output = StringIO()
        self.logger.debug('Running Rekall pslist plugin')
        s.RunPlugin("pslist", output=output)
        processes = self.parse_plugin_output(output)
        self.insert_db(processes)

    def parse_plugin_output(self, output):
        processes = []
        pslist = json.loads(output.getvalue())
        for e in pslist:
            e_type = e[0]
            if e_type == 'r':
                e_data = e[1]
                process_entry = {}
                process_entry['_EPROCESS'] = hex(e_data['_EPROCESS']['offset'])
                process_entry['name'] = e_data['_EPROCESS']['Cybox']['Name']
                process_entry['pid'] = e_data['_EPROCESS']['Cybox']['PID']
                process_entry['ppid'] = e_data['_EPROCESS']['Cybox']['Parent_PID']
                process_entry['thread_count'] = e_data['thread_count']
                process_entry['handle_count'] = e_data['handle_count']
                process_entry['wow64'] = e_data['wow64']
                self.logger.debug('Found process %s', process_entry)
                processes.append(process_entry)
        return processes

    def insert_db(self, processes):
        self.logger.info('Inserting processs list into database')
        process_nodes = []
        for p in processes:
            proc_node = Process(p['_EPROCESS'], p['name'], p['pid'], p['ppid'],
                           p['thread_count'], p['handle_count'], p['wow64'])
            self.graph.push(proc_node)
            process_nodes.append(proc_node)
        # signal the operating system Hook that the syscalls has been
        # inserted, to add the relationship
        self.context.trigger('processes_inserted', processes=process_nodes)