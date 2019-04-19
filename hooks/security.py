# sys
import subprocess
import json
import re
from pathlib import Path

# 3rd
from see import Hook


class SecurityHook(Hook):

    CHECKSEC_BIN = Path(__file__).parent.parent/"tools"/"checksec"/"checksec"

    def __init__(self, parameters):
        super().__init__(parameters)

        if not self.CHECKSEC_BIN.exists():
            raise RuntimeError('Cannot find checksec, did you forget to init the submodule ?')
        self.checksec = str(self.CHECKSEC_BIN)

        self.context.subscribe('filesystem_new_file_mime', self.check_file)

    def check_file(self, event):
        filepath = event.filepath
        inode = event.inode
        mime = event.mime
        if re.match(r'application/x(-pie)?-(executable|sharedlib)', mime):
            # run checksec and load json
            cmdline = [self.checksec, '--output', 'json', '--file', filepath]
            checksec_data = json.loads(subprocess.check_output(cmdline).decode())
            profile = checksec_data['file']

            def str2bool(string):
                return string.lower() in ['yes', 'true', 'y', '1']

            # update inode
            inode.checksec = True
            inode.relro = True if profile['relro'] in ["full", "partial"] else False
            inode.canary = str2bool(profile['canary'])
            inode.nx = str2bool(profile['nx'])
            inode.pie = profile['pie']
            inode.rpath = str2bool(profile['rpath'])
            inode.runpath = str2bool(profile['runpath'])
            inode.symtables = str2bool(profile['symtables'])
            inode.fortify_source = str2bool(profile['fortify_source'])
            inode.fortified = profile['fortified']
            inode.fortifyable = profile['fortify-able']
