# local
from hooks.memory import JsonRenderer, BASE_CONFIG_PATH

# 3rd
from see import Hook
from volatility.framework import automagic, plugins


class SyscallTableHook(Hook):

    def __init__(self, parameters):
        super().__init__(parameters)
        # config
        self.graph = self.configuration.get('graph', None)
        self.neo4j_enabled = self.configuration.get('neo4j_db', False)
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
