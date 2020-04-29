# local
# 3rd
from see import Hook

from hooks.memory import BASE_CONFIG_PATH, JsonRenderer
from oswatcher.model import Syscall
from volatility.framework import automagic, plugins


class SyscallTableHook(Hook):

    def __init__(self, parameters):
        super().__init__(parameters)
        # config
        self.graph = None
        self.os_node = None
        self.neo4j_enabled = self.configuration.get('neo4j', False)
        if self.neo4j_enabled:
            self.graph = self.configuration['neo4j']['graph']
            self.os_node = self.configuration['neo4j']['OS']
        self.debug = self.configuration.get('debug', False)
        self.context.subscribe('forensic_session', self.extract_syscall_table)

    def extract_syscall_table(self, event):
        ctx = event.context
        automagics = event.automagics
        plugin_list = event.plugin_list
        self.logger.info('Extracting the NT syscall table')
        try:
            plugin = plugin_list['windows.ssdt.SSDT']
        except KeyError as e:
            raise RuntimeError("Plugin not found") from e
        automagics = automagic.choose_automagic(automagics, plugin)
        constructed = plugins.construct_plugin(ctx, automagics, plugin, BASE_CONFIG_PATH, None, None)
        treegrid = constructed.run()
        renderer = JsonRenderer()
        renderer.render(treegrid)
        result = renderer.get_result()
        sdt = self.parse_ssdt_output(result)

        if self.neo4j_enabled:
            self.insert_neo4j_db(sdt)

        if self.debug:
            # print syscalls on debug output
            for table_name, table in sdt.items():
                self.logger.debug('Displaying table %s', table_name)
                for syscall in table:
                    self.logger.debug('[%s]: %s %s',
                                      syscall['Index'], syscall['Symbol'], hex(syscall['Address']))

    def parse_ssdt_output(self, ssdt_tables):
        sdt = {
            'Nt': [syscall for syscall in ssdt_tables if syscall['Module'] == 'ntoskrnl']
        }
        return sdt

    def insert_neo4j_db(self, sdt):
        for table_name, table in sdt.items():
            for syscall in table:
                syscall_node = Syscall(table_name, syscall['Index'], syscall['Symbol'], hex(syscall['Address']))
                syscall_node.owned_by.add(self.os_node)
                self.os_node.syscalls.add(syscall_node)
                self.graph.push(syscall_node)
