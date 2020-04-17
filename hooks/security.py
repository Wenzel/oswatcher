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
    """
    Security hook
    subscribes on filesystem events and runs security tools on binaries
    configuration:
    {
        "keep_failed_binaries": true // optional, whether we should keep the checksec failed binaires
        "keep_failed_dir": "/path/to/dir" // optional, path to directory where we should keep the failed binaires
                                                if not provided, a default one will be created in the current
                                                working directory: "{{ os_uuid }}_checksec_failed"

    }
    """

    CHECKSEC_BIN = Path(__file__).parent.parent / "tools" / "checksec" / "checksec"

    def __init__(self, parameters):
        super().__init__(parameters)

        if not self.CHECKSEC_BIN.exists():
            raise RuntimeError('Cannot find checksec, did you forget to init the submodule ?')
        self.os_node = self.configuration['neo4j']['OS']
        self.keep_binaries = self.configuration.get('keep_failed_binaries', False)
        # directory to dump executable on which checksec failed
        default_checksec_failed_dir = Path.cwd() / f"{self.os_node.id}_checksec_failed"
        self.keep_binaries_dir = self.configuration.get('keep_failed_dir', default_checksec_failed_dir)
        self.failed_count = 0

        self.checksec = str(self.CHECKSEC_BIN)

        self.context.subscribe('filesystem_new_file', self.check_file)

    def check_file(self, event):
        # event args
        inode = event.inode

        mime = inode.file_magic_type
        filepath = inode.path
        if re.match(r'application/x(-pie)?-(executable|sharedlib)', mime):
            self.logger.debug('%s: %s', filepath, mime)
            # this is a heavy call (download the file on the host filesystem through libguestfs appliance)
            # call it here once we filtered on the mime type provided by the file utility
            local_filepath = inode.local_file
            # run checksec and load json
            cmdline = [self.checksec, '--output=json', f'--file={local_filepath}']
            try:
                output = subprocess.check_output(cmdline).decode()
            except subprocess.CalledProcessError:
                self.failed_count += 1
                self.logger.warning("Checksec failed to analyze %s (%s)", filepath, inode.filecmd_output())
                if self.keep_binaries:
                    # copy file in checksec failed dir
                    self.keep_binaries_dir.mkdir(parents=True, exist_ok=True)
                    dst = self.keep_binaries_dir / inode.name
                    self.logger.warning("Dumping as %s", dst)
                    shutil.copy(inode.local_file, dst)
                return
            else:
                # load checksec JSON data and extract keys
                checksec_data = json.loads(subprocess.check_output(cmdline).decode())

                def str2bool(string):
                    return string.lower() in ['yes', 'true', 'y', '1']
                try:
                    profile = checksec_data[local_filepath]

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
                except KeyError as e:
                    self.failed_count += 1
                    self.logger.warning("Error while parsing checksec JSON output on %s (%s). Key %s does not exist",
                                        filepath, inode.filecmd_output(), e.args[0])
                    self.logger.warning("Full checksec output: %s", output)
                    if self.keep_binaries:
                        # copy file in checksec failed dir
                        self.keep_binaries_dir.mkdir(parents=True, exist_ok=True)
                        dst = self.keep_binaries_dir / inode.name
                        self.logger.warning("Dumping as %s", dst)
                        shutil.copy(inode.local_file, dst)
                    return

            checksec_file = ChecksecFile(relro, canary, nx, pie, rpath, runpath,
                                         symbols, fortify_source, fortified, fortifyable)
            self.context.trigger('security_checksec_bin', inode=inode, checksec_file=checksec_file)

    def cleanup(self):
        if self.failed_count:
            self.logger.info('Checksec failures count: %s', self.failed_count)
