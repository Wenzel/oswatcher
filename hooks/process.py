# local
from hooks.memory import JsonRenderer, BASE_CONFIG_PATH
from oswatcher.model import Process

# 3rd
from see import Hook
from volatility.framework import automagic, plugins


class ProcessListHook(Hook):

    def __init__(self, parameters):
        super().__init__(parameters)
        # config
        self.graph = self.configuration.get('graph')
        self.neo4j_enabled = self.configuration.get('neo4j_db', False)
        self.context.subscribe('forensic_session', self.extract_process_list)

    def extract_process_list(self, event):
        ctx = event.context
        automagics = event.automagics
        plugin_list = event.plugin_list
        self.logger.info('Extracting the process list')
        try:
            plugin = plugin_list['windows.pslist.PsList']
        except KeyError as e:
            raise RuntimeError("Plugin not found") from e
        automagics = automagic.choose_automagic(automagics, plugin)
        constructed = plugins.construct_plugin(ctx, automagics, plugin, BASE_CONFIG_PATH, None, None)
        treegrid = constructed.run()
        renderer = JsonRenderer()
        renderer.render(treegrid)
        result = renderer.get_result()
        processes = self.parse_plugin_output(result)
        if self.neo4j_enabled:
            self.insert_neo4j_db(processes)
        else:
            # print them on debug output
            for p in processes:
                self.logger.debug(p)

    def parse_plugin_output(self, pslist):
        processes = []
        for p in pslist:
            process_entry = {
                'name': p['ImageFileName'],
                'pid': p['PID'],
                'ppid': p['PPID'],
                'thread_count': p['Threads'],
                'handle_count': p['Handles'],
                'wow64': p['Wow64']
            }
            processes.append(process_entry)
        return processes

    def insert_neo4j_db(self, processes):
        self.logger.info('Inserting processs list into database')
        process_nodes = []
        for p in processes:
            proc_node = Process(p['name'], p['pid'], p['ppid'],
                                p['thread_count'], p['handle_count'], p['wow64'])
            self.graph.push(proc_node)
            process_nodes.append(proc_node)
        # signal the operating system Hook that the processes has been
        # inserted, to add the relationship
        self.context.trigger('processes_inserted', processes=process_nodes)
