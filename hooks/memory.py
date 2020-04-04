# sys
import logging
import os
import stat
import datetime
import shutil
from pathlib import Path
from typing import Any, List, Tuple, Dict, Optional
from tempfile import NamedTemporaryFile, TemporaryDirectory

# 3rd
import libvirt
from see import Hook
import volatility.plugins
from volatility import framework
from volatility.framework import contexts, automagic, interfaces
from volatility.framework.interfaces.renderers import RenderOption
from volatility.framework.renderers import format_hints
from volatility.cli.text_renderer import quoted_optional, hex_bytes_as_text, display_disassembly


BASE_CONFIG_PATH = 'plugins'


# customizing Volatility's JSON renderers
# this code is based on volatility.cli.text_renderer.JSONRenderer
# but the upstream class would always print the result on sys.stdout.
# here, we simply store the result in self.result, and return the data
# when get_result() is called

# storing this function in hooks.memory for now,
# may be removed when Volatility decided to implement a way
# to get the data in the upstream class
class JsonRenderer(interfaces.renderers.Renderer):
    _type_renderers = {
        format_hints.HexBytes: quoted_optional(hex_bytes_as_text),
        interfaces.renderers.Disassembly: quoted_optional(display_disassembly),
        datetime.datetime: lambda x: x.isoformat() if not isinstance(x, interfaces.renderers.BaseAbsentValue) else None,
        'default': lambda x: x
    }

    name = 'JSON'
    structured_output = True

    def __init__(self, options: Optional[List[RenderOption]] = None):
        self.result = None
        super().__init__(options)

    def get_render_options(self) -> List[RenderOption]:
        pass

    def get_result(self):
        """Outputs the JSON data to a file in a particular format"""
        return self.result

    def render(self, grid: interfaces.renderers.TreeGrid):
        final_output = ({}, [])

        def visitor(
                node: Optional[interfaces.renderers.TreeNode],
                accumulator: Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]],
        ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            acc_map, final_tree = accumulator
            node_dict = {'__children': []}
            for column_index in range(len(grid.columns)):
                column = grid.columns[column_index]
                renderer = self._type_renderers.get(column.type, self._type_renderers['default'])
                data = renderer(list(node.values)[column_index])
                if isinstance(data, interfaces.renderers.BaseAbsentValue):
                    data = None
                node_dict[column.name] = data
            if node.parent:
                acc_map[node.parent.path]['__children'].append(node_dict)
            else:
                final_tree.append(node_dict)
            acc_map[node.path] = node_dict

            return acc_map, final_tree

        if not grid.populated:
            grid.populate(visitor, final_output)
        else:
            grid.visit(node=None, function=visitor, initial_accumulator=final_output)

        self.result = final_output[1]


class MemoryDumpHook(Hook):

    def __init__(self, parameters):
        super().__init__(parameters)
        self.debug = self.configuration.get('debug', False)
        if not self.debug:
            # silence volatility
            logging.getLogger('volatility.framework').setLevel(logging.WARNING)
            logging.getLogger('volatility.plugins.yarascan').setLevel(logging.WARNING)
            logging.getLogger('volatility.schemas').setLevel(logging.WARNING)
        self.keep_dump = self.configuration.get('keep_dump', False)
        orig_domain_name = self.configuration['domain_name']
        default_dump_path = Path.cwd() / "{domain_name}-{tmp_uuid}.dump".format(
            domain_name=orig_domain_name, tmp_uuid=self.context.domain.name())
        self.keep_dump_path = Path(self.configuration.get('dump_path', default_dump_path))
        self.context.subscribe('desktop_ready', self.dump_memory)
        self.context.subscribe('memory_dumped', self.prepare_forensic_session)

    def dump_memory(self, event):
        # take temporary memory dump
        # we need to create our own tmp_dir
        # otherwise the dumpfile will be owned by libvirt
        # and we don't have the permission to remove it in /tmp
        with TemporaryDirectory() as tmp_dir:
            with NamedTemporaryFile(dir=tmp_dir, delete=not self.keep_dump) as ram_dump:
                # chmod to be r/w by everyone
                # before libvirt takes ownership
                os.chmod(ram_dump.name,
                         stat.S_IRUSR | stat.S_IWUSR
                         | stat.S_IRGRP | stat.S_IWGRP
                         | stat.S_IROTH | stat.S_IWOTH)
                # take dump
                self.logger.info('Dumping %s physical memory to %s',
                                 self.context.domain.name(), ram_dump.name)
                flags = libvirt.VIR_DUMP_MEMORY_ONLY
                dumpformat = libvirt.VIR_DOMAIN_CORE_DUMP_FORMAT_RAW
                self.context.domain.coreDumpWithFormat(ram_dump.name, dumpformat, flags)
                # trigger event
                self.context.trigger('memory_dumped', memdump_path=ram_dump.name)
                if self.keep_dump:
                    self.logger.info("Keeping memory dump at %s", self.keep_dump_path)
                    shutil.move(ram_dump.name, str(self.keep_dump_path))

    def prepare_forensic_session(self, event):
        memdump_path = event.memdump_path
        # init Volatility3
        failures = framework.import_files(volatility.plugins, True)
        if failures and self.debug:
            for f in failures:
                self.logger.debug('Plugin failed to load: %s', f)
        plugin_list = framework.list_plugins()
        ctx = contexts.Context()  # Construct a blank context
        automagics = automagic.available(ctx)  # Find all the automagics
        # populate ctx.config
        ctx.config['automagic.LayerStacker.single_location'] = Path(memdump_path).as_uri()
        self.context.trigger('forensic_session', context=ctx, automagics=automagics, plugin_list=plugin_list)
