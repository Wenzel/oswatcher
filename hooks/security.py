import re
import shutil
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from re import Match
from tempfile import NamedTemporaryFile
from typing import List

from checksec.elf import ELFSecurity, PIEType, RelroType, set_libc
from checksec.errors import ErrorNotAnElf, ErrorParsingFailed
from guestfs import GuestFS
from see import Hook

from hooks.filesystem import Inode
from oswatcher.model import OS, OSType


@dataclass
class ChecksecFile:
    relro: RelroType
    canary: bool
    nx: bool
    pie: PIEType
    rpath: bool
    runpath: bool
    symbols: bool
    fortified: bool
    fortify_source: int
    fortifyable: int


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

    def __init__(self, parameters):
        super().__init__(parameters)
        self.os_info = None
        self.stats: Counter = Counter()
        self.stats['total'] = 0
        self.local_guest_libc = NamedTemporaryFile()
        self.neo4j_enabled: bool = self.configuration.get('neo4j', False)
        if self.neo4j_enabled:
            self.os_node: OS = self.configuration['neo4j']['OS']
        self.keep_binaries: bool = self.configuration.get('keep_failed_binaries', False)
        # directory to dump executable on which checksec failed
        if self.neo4j_enabled:
            os_id = self.os_node.id
        else:
            os_id = self.context.domain.name()
        default_checksec_failed_dir: Path = Path.cwd() / f"{os_id}_checksec_failed"
        self.keep_binaries_dir: Path = Path(self.configuration.get('keep_failed_dir', default_checksec_failed_dir))

        self.context.subscribe('detected_os_info', self.get_os_info)
        self.context.subscribe('filesystem_capture_begin', self.download_libc)
        self.context.subscribe('filesystem_new_file', self.check_file)

    def get_os_info(self, event):
        self.os_info = event.os_info

    def download_libc(self, event):
        """Locate and download the libc"""
        gfs: GuestFS = event.gfs

        if not self.os_info:
            raise RuntimeError('Expected OS Info')

        if not self.os_info['os_type'] == OSType.Linux:
            return

        # find ldd
        cmd: List[str] = ['which', 'ldd']
        try:
            ldd_path: str = gfs.command(cmd).strip()
        except RuntimeError:
            self.logger.warning("Libc detection: command %s failed", cmd)
            return
        # find ls
        cmd: List[str] = ['which', 'ls']
        try:
            ls_path: str = gfs.command(cmd).strip()
        except RuntimeError:
            self.logger.warning("Libc detection: command %s failed", cmd)
            return
        cmd: List[str] = [ldd_path, ls_path]
        try:
            ldd_output: str = gfs.command(cmd).strip()
        except RuntimeError:
            self.logger.warning("Libc detection: command %s failed", cmd)
            return

        libc_inode = None
        for ldd_line in ldd_output.splitlines():
            m: Match = re.match(r'\t*(?P<libname>.*)\s+(=>)?\s+(?P<libpath>\S+)?\s+\((?P<addr>.*)\)$', ldd_line)
            if not m:
                self.logger.warn("Libc detection: line \"%s\" doesn't match LDD regex", ldd_line)
                continue
            if m.group('libname').startswith('libc.so'):
                # found guest libc
                libc_inode: Inode = Inode(self.logger, gfs, Path(m.group('libpath')))
                break
        if libc_inode is None:
            self.logger.warning("Libc detection: Couldn't locate libc !")
            return
        # copy libc
        shutil.copy(libc_inode.local_file, self.local_guest_libc.name)
        self.logger.info("Copied guest libc %s to %s", libc_inode.path, self.local_guest_libc.name)
        # setup checksec libc
        set_libc(Path(self.local_guest_libc.name))

    def check_file(self, event):
        # event args
        inode: Inode = event.inode

        if not self.os_info['os_type'] == OSType.Linux:
            # checksec only supports ELF files
            return
        mime: str = inode.file_magic_type
        filepath: Path = inode.path
        if re.match(r'application/x(-pie)?-(executable|sharedlib)', mime):
            self.logger.info('Checking security of %s: %s', filepath, mime)
            self.stats['total'] += 1
            # this is a heavy call (download the file on the host filesystem through libguestfs appliance)
            # call it here once we filtered on the mime type provided by the file utility
            local_filepath: Path = inode.local_file
            try:
                elf: ELFSecurity = ELFSecurity(local_filepath)
            except ErrorNotAnElf:
                self.stats['failed'] += 1
                self.logger.warning("Not a valid ELF file: %s (%s)", filepath, inode.gfs_file)
                return
            except ErrorParsingFailed:
                self.stats['failed'] += 1
                self.logger.warning("ELF parsing failed: %s (%s)", filepath, inode.gfs_file)
                if self.keep_binaries:
                    # copy file in checksec failed dir
                    self.keep_binaries_dir.mkdir(parents=True, exist_ok=True)
                    dst = self.keep_binaries_dir / inode.name
                    self.logger.warning("Dumping as %s", dst)
                    shutil.copy(inode.local_file, dst)
                return
            else:
                relro: RelroType = elf.relro
                canary: bool = elf.has_canary
                nx: bool = elf.has_nx
                pie: PIEType = elf.pie
                rpath: bool = elf.has_rpath
                runpath: bool = elf.has_runpath
                symbols: bool = not elf.is_stripped
                fortified: bool = elf.is_fortified
                fortify_source: int = len(elf.fortified)
                fortifyable: int = len(elf.fortifiable)

                checksec_file: ChecksecFile = ChecksecFile(relro, canary, nx, pie, rpath, runpath,
                                             symbols, fortify_source, fortified, fortifyable)
                self.logger.debug("Properties: %s", checksec_file)
                self.context.trigger('security_checksec_bin', inode=inode, checksec_file=checksec_file)
        else:
            # log mime for debugging
            self.logger.debug("Discard security analysis of %s: wrong mime type: %s", filepath, mime)

    def cleanup(self):
        if self.stats['total']:
            self.logger.info('Checksec stats: %s/%s', self.stats['total'], self.stats['failed'])
