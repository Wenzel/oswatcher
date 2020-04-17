# sys
import subprocess
import json
import re
import shutil
from pathlib import Path
from dataclasses import dataclass

# 3rd
from see import Hook


@dataclass
class ChecksecFile:
    relro: str
    canary: bool
    nx: bool
    pie: str
    rpath: bool
    runpath: bool
    symbols: bool
    fortify_source: bool
    fortified: bool
    fortifyable: bool


class SecurityHook(Hook):

    CHECKSEC_BIN = Path(__file__).parent.parent / "tools" / "checksec" / "checksec"

    def __init__(self, parameters):
        super().__init__(parameters)

        if not self.CHECKSEC_BIN.exists():
            raise RuntimeError('Cannot find checksec, did you forget to init the submodule ?')
        self.os_node = self.configuration['neo4j']['OS']
        self.checksec = str(self.CHECKSEC_BIN)
        # directory to dump executable on which checksec failed
        self.checksec_failed = Path.cwd() / f"{self.os_node.id}_checksec_failed"

        self.context.subscribe('filesystem_new_file', self.check_file)

    def check_file(self, event):
        # event args
        inode = event.inode

        mime = inode.mime_type
        filepath = inode.str_path
        if re.match(r'application/x(-pie)?-(executable|sharedlib)', mime):
            self.logger.debug('%s: %s', filepath, mime)
            # run checksec and load json
            cmdline = [self.checksec, '--output=json', f'--file={filepath}']
            try:
                checksec_data = json.loads(subprocess.check_output(cmdline).decode())
                profile = checksec_data[filepath]
                self.logger.debug('profile: %s', profile)

                def str2bool(string):
                    return string.lower() in ['yes', 'true', 'y', '1']

                relro = profile['relro']
                canary = str2bool(profile['canary'])
                nx = str2bool(profile['nx'])
                pie = profile['pie']
                rpath = str2bool(profile['rpath'])
                runpath = str2bool(profile['runpath'])
                symbols = str2bool(profile['symbols'])
                fortify_source = str2bool(profile['fortify_source'])
                fortified = profile['fortified']
                fortifyable = profile['fortify-able']
            except (subprocess.CalledProcessError, KeyError):
                # copy file in checksec failed dir
                self.checksec_failed.mkdir(parents=True, exist_ok=True)
                dst = self.checksec_failed / inode.name
                self.logger.warning("Checksec failed to analyze %s (%s). Dumping as %s", filepath, mime, dst)
                shutil.copy(inode.local_file, dst)
                return

            checksec_file = ChecksecFile(relro, canary, nx, pie, rpath, runpath,
                                         symbols, fortify_source, fortified, fortifyable)
            self.context.trigger('security_checksec_bin', inode=inode, checksec_file=checksec_file)
