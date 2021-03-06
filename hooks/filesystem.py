from __future__ import annotations

import functools
import logging
import re
import shutil
import stat
import time
import typing
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, Optional

import guestfs
import magic
from git import Repo
from git.exc import GitCommandError
from memory_tempfile import MemoryTempfile
from see import Hook

from oswatcher.model import GraphInode, InodeType, OSType
from oswatcher.utils import get_hard_drive_path

if typing.TYPE_CHECKING:
    from guestfs import GuestFS
    from hooks.security import ELFChecksec
    from hooks.static_analyzer import PEChecksec

STATS = Counter()
try:
    TEMPFILE = MemoryTempfile(fallback=False)
except RuntimeError:
    logging.warning("Memory-based filesystem not available for temporary files. Fallback to disk-based")
    TEMPFILE = MemoryTempfile(fallback=True)


class Inode:

    def __init__(self, gfs, node):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._gfs = gfs
        self._tmp_local_file = None
        # public attributes
        self.path = node
        self.name = self.path.name
        if self.name == '':
            self.name = '/'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        if self._tmp_local_file:
            self._tmp_local_file.close()

    @property
    def exists(self) -> bool:
        return self._gfs.exists(self.str_path)

    @property
    @functools.lru_cache()
    def str_path(self) -> str:
        return str(self.path)

    @property
    @functools.lru_cache()
    def status(self):
        return self._gfs.lstatns(self.str_path)

    @property
    @functools.lru_cache()
    def size(self):
        return self.status['st_size']

    @property
    @functools.lru_cache()
    def mode(self):
        return stat.filemode(self.status['st_mode'])

    @property
    @functools.lru_cache()
    def inode_type(self):
        return InodeType(stat.S_IFMT(self.status['st_mode']))

    @property
    @functools.lru_cache()
    def is_setuid(self):
        return True if self.status['st_mode'] & stat.S_ISUID else False

    @property
    @functools.lru_cache()
    def is_setgid(self):
        return True if self.status['st_mode'] & stat.S_ISGID else False

    @property
    @functools.lru_cache()
    def is_sticky(self):
        return True if self.status['st_mode'] & stat.S_ISVTX else False

    @property
    @functools.lru_cache()
    def inode_type_value(self):
        return self.inode_type.value

    @property
    @functools.lru_cache()
    def local_file(self) -> str:
        STATS['local_file'] += 1
        self._tmp_local_file = TEMPFILE.NamedTemporaryFile()
        self._gfs.download(self.str_path, self._tmp_local_file.name)
        return self._tmp_local_file.name

    @functools.lru_cache()
    def filecmd_output(self, mime_option=False) -> Optional[str]:
        """Run the file utility and returns the output"""
        if not self.inode_type == InodeType.REG:
            return None
        STATS['filecmd_output'] += 1
        file_cmd = ['file', self.str_path]
        if mime_option:
            file_cmd.append('-i')
        return self._gfs.command(file_cmd).strip()

    @property
    @functools.lru_cache()
    def gfs_file(self) -> Optional[str]:
        if not self.inode_type == InodeType.REG:
            return None
        STATS['guestfs_file'] += 1
        return self._gfs.file(self.str_path)

    @property
    @functools.lru_cache()
    def file_magic_type(self) -> Optional[str]:
        """this method is faster than py_magic_type, since it doesn't involve
        downloading the whole file to the host"""
        STATS['file_magic_type'] += 1
        file_mime_output = self.filecmd_output(mime_option=True)
        # output example
        # /usr/src/xxx/asm/user.h: /usr/src/xxx/asm/user.h: application/octet-stream
        # /usr/bin/xz: application/x-pie-executable; charset=binary
        regex = r'^(.*:)+\s+(?P<mime_type>.*/[^;]+).*$'
        m = re.match(regex, file_mime_output)
        if not m:
            self._logger.warning('Failed to parse MIME type from file command output: %s: %s',
                                 self.path, file_mime_output)
            return None
        return m.group('mime_type')

    @property
    @functools.lru_cache()
    def py_magic_type(self) -> Optional[str]:
        if not self.inode_type == InodeType.REG:
            return None
        STATS['py_magic_type'] += 1
        return magic.from_file(self.local_file, mime=True)


class GuestFSWrapper:
    """
    A wrapper around the libguestfs instance GuestFS object
    which provides helpers to easily walk through the filesystem
    """
    def __init__(self, guestfs_instance: GuestFS):
        self._gfs = guestfs_instance
        self.logger = logging.getLogger(self.__class__.__name__)

    def walk(self, node: Path, func: Callable[[Path], Any] = None) -> Iterator[Any]:
        """
        walks the filesystem at the given path, yield the return value of the given function
        :param node: the guest Path from which to start walking
        :param func: a lambda function whose return value will be yielded. If not specified, the yielded value
                    will be the current guest filepath
        :return: and iterator a values returned by the specified lambda function
        """
        if not func:
            yield node
        else:
            yield func(node)
        if self._gfs.is_dir(str(node)):
            for entry in self.list_entries(str(node)):
                subnode_abs = node / entry
                yield from self.walk(subnode_abs, func)

    def walk_inodes(self, node: Path) -> Iterator[Inode]:
        yield from self.walk(node, lambda cur_node: Inode(self._gfs, cur_node))

    def list_entries(self, folder: str) -> Iterator[str]:
        # assume that node is a directory
        # workaround bugs in libguestfs
        try:
            yield from self._gfs.ls(str(folder))
        except UnicodeDecodeError as e:
            # reported: https://bugzilla.redhat.com/show_bug.cgi?id=1778962
            self.logger.warning("libguestfs failed to list entries of %s directory: %s", str(folder), str(e))
        except RuntimeError as e:
            # TODO: report bug
            self.logger.warning("libguestfs failed to list entries of %s directory: %s", str(folder), str(e))


class LibguestfsHook(Hook):

    def __init__(self, parameters):
        super().__init__(parameters)
        self.gfs: Optional[GuestFS] = None
        self.os_type = None
        self.neo4j = self.configuration.get('neo4j', False)
        self.os_node = None
        if self.neo4j:
            self.os_node = self.configuration['neo4j']['OS']
        self.context.subscribe('protocol_start', self.init_libguestfs)

    def init_libguestfs(self, event):
        self.logger.info('Initializing libguestfs')
        self.gfs = guestfs.GuestFS(python_return_dict=True)
        # attach libvirt domain
        qcow_path = get_hard_drive_path(self.context.domain)
        self.logger.debug('Hard drive: %s', qcow_path)
        self.gfs.add_libvirt_dom(self.context.domain, readonly=True)
        self.logger.debug('Running libguestfs backend')
        self.gfs.launch()
        os_partitions = self.gfs.inspect_os()
        detected = False
        if len(os_partitions) == 0:
            main_partition = self.gfs.list_partitions()[0]
            self.logger.warning("No OS detected, using first partition: %s", main_partition)
        else:
            detected = True
            # capture first detected OS
            main_partition = os_partitions[0]
            os_type_str = self.gfs.inspect_get_type(main_partition)
            try:
                self.os_type = OSType[os_type_str.capitalize()]
            except KeyError:
                raise RuntimeError("Unhandled OS type {}".format(os_type_str.capitalize()))

        self.logger.debug('Mounting filesystem')
        self.gfs.mount_ro(main_partition, '/')
        # now that fs is mounted we call inspect it if we need it
        if not detected:
            # quick guess of ostype based on /proc presence
            if self.gfs.is_dir('/proc'):
                self.os_type = OSType.Linux
            else:
                self.os_type = OSType.Windows
        # build os_info
        os_info = {
            'os_type': self.os_type
        }
        self.logger.info("OS type: %s", self.os_type.name)
        # update OS node
        if self.neo4j:
            self.os_node.type = os_info['os_type'].name
        # emit triggers
        self.context.trigger('detected_os_info', os_info=os_info)
        self.context.trigger('guestfs_instance', gfs=self.gfs)

    def cleanup(self):
        # shutdown
        self.logger.debug('shutdown libguestfs')
        try:
            self.gfs.umount_all()
            self.gfs.shutdown()
        except RuntimeError:
            # not launched
            pass


class FilesystemHook(Hook):
    """
    The FilesystemHook will walk through the guest main filesystem using libguestfs.
    The main filesystem is either the main partition, determined by OS inspection methods from libguestfs,
    or using the first partition if OS is unknown after inspection

    Configuration:

    enumerate: Optional - Whether we should walk through the entire filesystem once to get a progress percentage
                            on the real filesystem capture, which can be long
    log_progress: Optional - Whether we should display a status update of the capture in the logs
    log_progress_delay: Optional - How often to update the capture progress status
    filter_exclude: Optional - Define exclude filesystem filters for the capture
                        Filter can be defined using 'extensions' or 'mimes' (MIME types)
                        Specifying both will result in 'extensions' being applied first
    filter_include: Optional - Include filters, rest is ignored. See filters_exclude for the description
    """

    def __init__(self, parameters):
        super().__init__(parameters)
        # config
        self.enumerate = self.configuration.get('enumerate', False)
        self.log_progress = self.configuration.get('log_progress', True)
        self.log_progress_delay = int(self.configuration.get('log_progress_delay', 0))
        self.filter_include = self.configuration.get('filter_include')
        self.filter_exclude = self.configuration.get('filter_exclude')

        self.gfs = None
        self.gfs_wrapper = None
        self.tx = None
        self.counter = 0
        self.total_entries = 0
        self.time_last_update = 0
        self.context.subscribe('offline', self.capture_fs)
        self.context.subscribe('guestfs_instance', self.get_guestfs_instance)

    def filter_node(self, inode: Inode):
        """Use filters defined in hook configuration to determine if
        this node should be included or excluded from the filesystem capture"""
        # check exclude first
        if self.filter_exclude:
            # extensions
            try:
                extensions = self.filter_exclude['extensions']
            except KeyError:
                pass
            else:
                if inode.path.suffix in extensions:
                    self.logger.debug('filters_exclude[extensions]: excluding %s', inode.path)
                    return False
            # mimes
            try:
                mimes = self.filter_exclude['mimes']
            except KeyError:
                pass
            else:
                if inode.py_magic_type in mimes:
                    self.logger.debug('filters_exclude[mimes]: excluding %s', inode.path)
                    return False

        # check include now
        if not self.filter_include:
            # always include
            return True

        # extensions
        try:
            extensions = self.filter_include['extensions']
        except KeyError:
            pass
        else:
            if inode.path.suffix not in extensions:
                self.logger.debug('filters_include[extensions]: excluding %s', inode.path)
                return False
        # mimes
        try:
            mimes = self.filter_include['mimes']
        except KeyError:
            pass
        else:
            if inode.py_magic_type not in mimes:
                self.logger.debug('filters_include[mimes]: excluding %s', inode.path)
                return False

        return True

    def list_entries(self, node):
        # assume that node is a directory
        # workaround bugs in libguestfs
        try:
            return self.gfs.ls(str(node))
        except UnicodeDecodeError as e:
            # reported: https://bugzilla.redhat.com/show_bug.cgi?id=1778962
            self.logger.warning("libguestfs failed to list entries of %s directory: %s", str(node), str(e))
        except RuntimeError as e:
            # TODO: report bug
            self.logger.warning("libguestfs failed to list entries of %s directory: %s", str(node), str(e))

        return []

    def get_guestfs_instance(self, event):
        """SEE signal handler to simply retrieve the libguestfs instance"""
        self.gfs = event.gfs
        self.gfs_wrapper = GuestFSWrapper(self.gfs)

    def capture_fs(self, event):
        if self.gfs is None:
            raise RuntimeError('Hook didnt receive libguestfs instance')
        root = Path('/')
        if self.enumerate:
            self.logger.info('Enumerating entries')
            self.total_entries = sum(1 for _ in self.gfs_wrapper.walk(root))
        self.logger.info('Capturing filesystem')
        self.time_last_update = time.time()

        self.context.trigger('filesystem_capture_begin')
        root_inode = self.walk_capture(root)
        # cleanup inode related resources
        root_inode.close()
        self.context.trigger('filesystem_capture_end', root=root_inode)

    def walk_capture(self, node):
        self.counter += 1
        # logging the progress ?
        if self.log_progress:
            self.update_log(node)
        # process current node
        self.logger.debug('inode path: %s', node)
        name = node.name
        # root
        if not name:
            name = node.anchor
        inode = Inode(self.gfs, node)
        # apply filters
        if self.filter_node(inode):
            self.context.trigger('filesystem_new_inode', gfs=self.gfs, inode=inode, gfs_wrapper=self.gfs_wrapper)
        # download and execute trigger on local file, if not filtered
        if inode.inode_type == InodeType.REG:
            # apply filters
            if self.filter_node(inode):
                self.context.trigger('filesystem_new_file', gfs=self.gfs, inode=inode, gfs_wrapper=self.gfs_wrapper)
        # walk
        if self.gfs.is_dir(str(node)):
            entries = self.list_entries(node)
            for entry in entries:
                subnode_abs = node / entry
                child_inode = self.walk_capture(subnode_abs)
                # apply filters
                if self.filter_node(inode):
                    self.context.trigger('filesystem_new_child_inode', gfs=self.gfs, inode=inode, child=child_inode,
                                         gfs_wrapper=self.gfs_wrapper)
                # cleanup inode related resources
                child_inode.close()

        # apply filters
        if self.filter_node(inode):
            self.context.trigger('filesystem_end_inode', gfs=self.gfs, inode=inode, gfs_wrapper=self.gfs_wrapper)
        return inode

    def update_log(self, node):
        delta = time.time() - self.time_last_update
        if delta > self.log_progress_delay:
            if self.enumerate:
                perc = round(self.counter * 100 / self.total_entries, 1)
                self.logger.info("[{} %] {}".format(perc, node))
            else:
                self.logger.info(node)
            # reset
            self.time_last_update = time.time()

    def cleanup(self):
        self.logger.info('Inode statistics: %s', STATS)


class Neo4jFilesystemHook(Hook):

    def __init__(self, parameters):
        super().__init__(parameters)
        # config
        self.neo4j_enabled = self.configuration.get('neo4j', False)
        if not self.neo4j_enabled:
            raise RuntimeError('Neo4j plugin selected but neo4j is disabled in configuration')
        self.graph = self.configuration['neo4j']['graph']
        self.os_node = self.configuration['neo4j']['OS']
        self.root_g_inode: GraphInode = None
        self.tx = None
        self.os_info = None
        self.fs: Dict[str, GraphInode] = {}
        self.context.subscribe('detected_os_info', self.get_os_info)
        self.context.subscribe('filesystem_capture_begin', self.fs_capture_begin)
        self.context.subscribe('filesystem_capture_end', self.fs_capture_end)
        self.context.subscribe('filesystem_new_inode', self.process_new_inode)
        self.context.subscribe('filesystem_new_child_inode', self.process_new_child)
        self.context.subscribe('filesystem_end_inode', self.process_end_inode)
        self.context.subscribe('checksec_elf', self.process_checksec_elf)
        self.context.subscribe('checksec_pe', self.process_checksec_pe)

    def get_os_info(self, event):
        """SEE signal handler to simply retrieve the os_info"""
        self.os_info = event.os_info

    def fs_capture_begin(self, event):
        # start py2neo transaction
        # call self.graph.create() for each inode would be way too slow
        self.tx = self.graph.begin()

    def fs_capture_end(self, event):
        # commit transaction
        self.tx.commit()
        # update OS node
        self.os_node.root_filesystem.add(self.root_g_inode)
        self.root_g_inode.owned_by.add(self.os_node)
        # push root relationship
        self.graph.push(self.root_g_inode)

    def process_new_inode(self, event):
        inode = event.inode
        # create graph object
        g_inode = GraphInode(inode, self.os_info['os_type'])
        # add to fs dict for process_new_child callback
        self.fs[inode.str_path] = g_inode
        # set root_g_inode
        if inode.path == Path('/'):
            self.root_g_inode = g_inode

    def process_new_child(self, event):
        inode = event.inode
        child = event.child
        g_inode = self.fs[inode.str_path]
        g_child_inode = self.fs[child.str_path]
        g_inode.children.add(g_child_inode)
        # graph object has been inserted into children list
        # we can safely remove it
        del self.fs[child.str_path]

    def process_end_inode(self, event):
        inode = event.inode
        g_inode = self.fs[inode.str_path]
        # insert into Neo4j transaction
        self.tx.create(g_inode)

    def process_checksec_elf(self, event):
        inode: Inode = event.inode
        elfsec: ELFChecksec = event.elf_checksec
        self.fs[str(inode.path)].checksec = True
        self.fs[str(inode.path)].relro = elfsec.relro
        self.fs[str(inode.path)].canary = elfsec.canary
        self.fs[str(inode.path)].nx = elfsec.nx
        self.fs[str(inode.path)].pie = elfsec.pie
        self.fs[str(inode.path)].rpath = elfsec.rpath
        self.fs[str(inode.path)].runpath = elfsec.runpath
        self.fs[str(inode.path)].symbols = elfsec.symbols
        self.fs[str(inode.path)].fortify_source = elfsec.fortify_source
        self.fs[str(inode.path)].fortified = elfsec.fortified
        self.fs[str(inode.path)].fortifyable = elfsec.fortifyable

    def process_checksec_pe(self, event):
        inode: Inode = event.inode
        pesec: PEChecksec = event.pe_checksec
        self.fs[inode.str_path].checksec = True
        self.fs[inode.str_path].dynamic_base = pesec.dynamic_base
        self.fs[inode.str_path].no_seh = pesec.no_seh
        self.fs[inode.str_path].guard_cf = pesec.guard_cf
        self.fs[inode.str_path].force_integrity = pesec.force_integrity
        self.fs[inode.str_path].nx_compat = pesec.nx_compat
        self.fs[inode.str_path].high_entropy_va = pesec.high_entropy_va
        self.fs[inode.str_path].signed = pesec.signed
        self.fs[inode.str_path].cat_filepath = pesec.cat_filepath


class GitFilesystemHook(Hook):
    # size of the batch of files to remove for git rm command line
    # a too long command line will raise a GitCommandError
    # we can reduce this number if that happens in the future
    RM_BATCH_SIZE = 1000

    """
    Hook configuration example:
    "configuration":
            {
                "repo": "/path/to/repo",
                "file_content": false,
                "commit_message": "",
                "remove_exclusion": [
                    "README.md",
                    "WINDOWS/system32/calc.exe"
                ]
            }

    parameters:
    - repo: (mandatory) path to the git repo
    - file_content: (optional) whether we should copy the file content. If false, it creates an empty file instead
    - commit_message: (optional) specifies the commit message to be used
    - remove_exclusion: (optional) a list of files to avoid removing from the old filesystem
    """

    def __init__(self, parameters):
        super().__init__(parameters)
        self.repo_path = Path(self.configuration['repo'])
        self.commit_message = self.configuration.get('commit_message', None)
        self.file_content = self.configuration.get('file_content', False)
        self.remove_exclusion = [Path(p) for p in self.configuration.get('remove_exclusion', [])]
        self.repo = Repo(str(self.repo_path))
        # repo must be clean
        if self.repo.is_dirty():
            raise RuntimeError("Repository is dirty. Aborting.")

        # we need to remove the old filesystem at the end of the capture
        # run git ls-files
        # build a dict to be more efficient
        self.to_remove_tree = {}
        # git ls-files doesn't like some characters like '’'
        # and a filename: First_One’s_Free_.scale-100.png
        # will return as: "First_One\342\200\231s_Free_.scale-100.png"
        # we skip this file
        # TODO: how to handle special chars -> \342\200\231 ?
        for p in [Path(p) for p in self.repo.git.ls_files().split('\n') if not p.startswith("\"")]:
            parts = p.parts
            current = self.to_remove_tree
            # iterate on all subdirectories, except filename
            for branch in parts[:-1]:
                current = current.setdefault(branch, {})
            # add filename
            current[p.name] = True

        if self.file_content:
            self.context.subscribe('filesystem_new_file', self.process_new_file)
        else:
            # only capture filesystem tree
            self.context.subscribe('filesystem_new_inode', self.process_new_inode)
        self.context.subscribe('filesystem_capture_end', self.fs_capture_end)

    def process_new_inode(self, event):
        inode = event.inode

        relpath = inode.path.relative_to('/')
        filepath = self.repo_path / relpath
        # test if exists
        if not filepath.exists():
            if InodeType(inode.inode_type) == InodeType.DIR:
                filepath.mkdir(parents=True, exist_ok=True)
            else:
                # everything else is treated as file
                filepath.parent.mkdir(parents=True, exist_ok=True)
                filepath.touch()
        elif InodeType(inode.inode_type) != InodeType.DIR:
            # exists and is a file
            try:
                # processing a guest path that already exists in git
                # so it was part of the old filesystem
                # so we should avoid removing it as part of the final git rm ...
                # and so we should remove it from the old filesystem removal tree dict
                current = self.to_remove_tree
                parts = relpath.parts
                for subdir in parts[:-1]:
                    current = current[subdir]
                if current[relpath.name]:
                    del current[relpath.name]
            except KeyError:
                self.logger.warning("Couldn't remove %s from old filesystem removal tree", relpath)

    def process_new_file(self, event):
        inode = event.inode
        local_tmp_filepath = inode.local_file

        local_git_filepath = self.repo_path / inode.path.relative_to('/')
        # test if exists
        if not local_git_filepath.exists():
            if InodeType(inode.inode_type) == InodeType.DIR:
                local_git_filepath.mkdir(parents=True, exist_ok=True)
            else:
                # everything else is treated as file
                local_git_filepath.parent.mkdir(parents=True, exist_ok=True)
                # copy file content
                shutil.copyfile(local_tmp_filepath, local_git_filepath)

    def fs_capture_end(self, event):
        # 1 - commit removed files
        # remove exclusion
        for p in self.remove_exclusion:
            try:
                current = self.to_remove_tree
                parts = p.parts
                for branch in parts[:-1]:
                    current = current[branch]
                del current[p.name]
            except KeyError:
                self.logger.warning("could not exclude %s from remove list", p)

        # list of git files to be removed
        # converted from dict to string for self.repo.index.remove
        to_remove_list = []

        def walk_rm_tree(d, ancestors):
            for k, v in d.items():
                if isinstance(v, dict):
                    ancestors.append(k)
                    walk_rm_tree(v, ancestors)
                    ancestors.pop()
                else:
                    # remove file
                    p = Path(self.repo_path)
                    for subdir in ancestors:
                        p = p / subdir
                    # add filename
                    p = p / k
                    self.logger.debug("removing: %s", p)
                    to_remove_list.append(str(p))

        self.logger.info("Removing files from the previous filesystem")
        walk_rm_tree(self.to_remove_tree, [])
        # cut the list in chunks
        # otherwise OSError: [Errno 7] Argument list too long: 'git'
        for i in range(0, len(to_remove_list), self.RM_BATCH_SIZE):
            chunk = to_remove_list[i:i + self.RM_BATCH_SIZE]
            self.repo.index.remove(chunk, working_tree=True, r=True)

        # override default message by user defined commit message
        message = self.configuration['domain_name']
        if self.commit_message is not None and self.commit_message:
            message = self.commit_message

        rm_message = '[RM] {}'.format(message)
        try:
            self.logger.info('Creating new commit \'%s\'', rm_message)
            self.repo.git.commit('-m', rm_message)
        except GitCommandError:
            self.logger.warning("Working tree is clean, nothing to commit !")
        self.logger.info("Removed %s files", len(to_remove_list))

        # 2 - commit new files
        self.logger.info('Adding all files in the working tree')
        to_add = self.repo.untracked_files
        self.repo.git.add('-A')

        add_message = '[ADD] {}'.format(message)
        try:
            self.logger.info('Creating new commit \'%s\'', add_message)
            self.repo.git.commit('-m', add_message)
        except GitCommandError:
            self.logger.warning("Working tree is clean, nothing to commit !")
        self.logger.info("Added %s files", len(to_add))
