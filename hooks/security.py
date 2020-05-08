# sys
import json
import re
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

# 3rd
from see import Hook

# local
from oswatcher.model import OSType


@dataclass
class ELFChecksec:
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
        self.os_info = None
        self.stats = Counter()
        self.stats['total'] = 0
        # find checksec in path first
        self.checksec = shutil.which('checksec')
        if not self.checksec:
            # use checksec version distributed with oswatcher
            if not self.CHECKSEC_BIN.exists():
                raise RuntimeError('Cannot find checksec, did you forget to init the submodule ?')
            self.checksec = str(self.CHECKSEC_BIN)
        self.neo4j_enabled = self.configuration.get('neo4j', False)
        if self.neo4j_enabled:
            self.os_node = self.configuration['neo4j']['OS']
        self.keep_binaries = self.configuration.get('keep_failed_binaries', False)
        # directory to dump executable on which checksec failed
        if self.neo4j_enabled:
            os_id = self.os_node.id
        else:
            os_id = self.context.domain.name()
        default_checksec_failed_dir = Path.cwd() / f"{os_id}_checksec_failed"
        self.keep_binaries_dir = Path(self.configuration.get('keep_failed_dir', default_checksec_failed_dir))

        self.context.subscribe('detected_os_info', self.get_os_info)
        self.context.subscribe('filesystem_new_file', self.check_file)

    def get_os_info(self, event):
        self.os_info = event.os_info

    def check_file(self, event):
        # event args
        inode = event.inode

        if not self.os_info['os_type'] == OSType.Linux:
            # checksec only supports ELF files
            return
        mime = inode.file_magic_type
        if not mime:
            return
        filepath = inode.path
        if re.match(r'application/x(-pie)?-(executable|sharedlib)', mime):
            self.logger.info('Checking security of %s: %s', filepath, mime)
            self.stats['total'] += 1
            # this is a heavy call (download the file on the host filesystem through libguestfs appliance)
            # call it here once we filtered on the mime type provided by the file utility
            local_filepath = inode.local_file
            # run checksec and load json
            cmdline = [self.checksec, '--output=json', f'--file={local_filepath}']
            try:
                output = subprocess.check_output(cmdline).decode()
            except subprocess.CalledProcessError:
                self.stats['failed'] += 1
                self.logger.warning("Checksec failed to analyze %s (%s)", filepath, inode.gfs_file)
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
                    self.stats['failed'] += 1
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

            elfsec = ELFChecksec(relro, canary, nx, pie, rpath, runpath,
                                 symbols, fortify_source, fortified, fortifyable)
            self.logger.debug("Properties: %s", elfsec)
            self.context.trigger('checksec_elf', inode=inode, elf_checksec=elfsec)
        else:
            # log mime for debugging
            self.logger.debug("Discard security analysis of %s: wrong mime type: %s", filepath, mime)

    def cleanup(self):
        if self.stats['total']:
            self.logger.info('Checksec stats: %s/%s', self.stats['total'], self.stats['failed'])
