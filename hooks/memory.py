# sys
import logging
import os
import stat
from tempfile import NamedTemporaryFile, TemporaryDirectory

# 3rd
import libvirt
from see import Hook
# silence rekall output
logger = logging.getLogger()
log_level = logger.getEffectiveLevel()
logger.setLevel(logging.CRITICAL)
from rekall import plugins, session
# restore our logging level
logger.setLevel(log_level)


class MemoryDumpHook(Hook):

    def __init__(self, parameters):
        super().__init__(parameters)
        debug = self.configuration.get('debug', False)
        if not debug:
            # silence rekall output
            logging.getLogger('rekall.1').setLevel(logging.CRITICAL)
        self.context.subscribe('desktop_ready', self.dump_memory)
        self.context.subscribe('memory_dumped', self.prepare_rekall_session)

    def dump_memory(self, event):
        # take temporary memory dump
        # we need to create our own tmp_dir
        # otherwise the dumpfile will be owned by libvirt
        # and we don't have the permission to remove it in /tmp
        with TemporaryDirectory() as tmp_dir:
            with NamedTemporaryFile(dir=tmp_dir) as ram_dump:
                # chmod to be r/w by everyone
                # before libvirt takes ownership
                os.chmod(ram_dump.name,
                         stat.S_IRUSR | stat.S_IWUSR |
                         stat.S_IRGRP | stat.S_IWGRP |
                         stat.S_IROTH | stat.S_IWOTH)
                # take dump
                self.logger.info('Dumping %s physical memory to %s',
                                 self.context.domain.name(), ram_dump.name)
                flags = libvirt.VIR_DUMP_MEMORY_ONLY
                dumpformat = libvirt.VIR_DOMAIN_CORE_DUMP_FORMAT_RAW
                self.context.domain.coreDumpWithFormat(ram_dump.name, dumpformat, flags)
                # trigger event
                self.context.trigger('memory_dumped', memdump_path=ram_dump.name)

    def prepare_rekall_session(self, event):
        memdump_path = event.memdump_path
        s = session.Session(
            filename=memdump_path,
            autodetect=["rsds"],
            autodetect_build_local='none',
            format='data',
            profile_path=[
                "http://profiles.rekall-forensic.com"
            ]
        )
        self.context.trigger('rekall_session', session=s)
