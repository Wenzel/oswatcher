# sys
import time
import stat
import shutil
import functools
from enum import Enum
from tempfile import NamedTemporaryFile
from pathlib import Path
from contextlib import contextmanager

# local
from oswatcher.model import GraphInode

# 3rd
import guestfs
import magic
from see import Hook
from git import Repo


class InodeType(Enum):
    DIR = stat.S_IFDIR
    CHR = stat.S_IFCHR
    BLK = stat.S_IFBLK
    REG = stat.S_IFREG
    FIFO = stat.S_IFIFO
    LNK = stat.S_IFLNK
    SOCK = stat.S_IFSOCK
    DOOR = stat.S_IFDOOR


class Inode:

    def __init__(self, gfs, node):
        self._gfs = gfs
        self._tmp_local_file = None
        # public attributes
        self.path = node
        self.name = self.path.name

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        if self._tmp_local_file:
            self._tmp_local_file.close()

    @property
    @functools.lru_cache()
    def str_path(self):
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
        return InodeType(stat.S_IFMT(self.status['st_mode'])).value

    @property
    @functools.lru_cache()
    def local_file(self):
        self._tmp_local_file = NamedTemporaryFile()
        self._gfs.download(self.str_path, self._tmp_local_file.name)
        return self._tmp_local_file.name

    @property
    @functools.lru_cache()
    def mime_type(self):
        return magic.from_file(self.local_file, mime=True)


@contextmanager
def guestfs_instance(self):
    self.logger.info('Initializing libguestfs')
    gfs = guestfs.GuestFS(python_return_dict=True)
    # attach libvirt domain
    gfs.add_libvirt_dom(self.context.domain, readonly=True)
    self.logger.debug('Running libguestfs backend')
    gfs.launch()
    try:
        os_partitions = gfs.inspect_os()
        if len(os_partitions) == 0:
            main_partition = gfs.list_partitions()[0]
            self.logger.warning("No OS detected, using first partition: %s", main_partition)
        else:
            # capture first detected OS
            main_partition = os_partitions[0]
        self.logger.debug('Mounting filesystem')
        gfs.mount_ro(main_partition, '/')
        yield gfs
    finally:
        # shutdown
        self.logger.debug('shutdown libguestfs')
        gfs.umount_all()
        gfs.shutdown()


class FilesystemHook(Hook):

    def __init__(self, parameters):
        super().__init__(parameters)
        # config
        self.enumerate = self.configuration.get('enumerate', False)
        self.log_progress = self.configuration.get('log_progress', True)
        self.log_progress_delay = int(self.configuration.get('log_progress_delay', 0))
        self.inode_checksums = self.configuration.get('inode_checksums', False)

        self.gfs = None
        self.tx = None
        self.counter = 0
        self.total_entries = 0
        self.time_last_update = 0
        self.context.subscribe('offline', self.capture_fs)

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

    def capture_fs(self, event):
        with guestfs_instance(self) as gfs:
            self.gfs = gfs
            root = Path('/')
            if self.enumerate:
                self.logger.info('Enumerating entries')
                self.walk_count(root)
            self.logger.info('Capturing filesystem')
            self.time_last_update = time.time()

            self.context.trigger('filesystem_capture_begin')
            root_inode = self.walk_capture(root)
            # cleanup inode related resources
            root_inode.close()
            # signal the operating system hook
            # that the FS has been inserted
            # and send it the root_inode to build the relationship
            # (used by Neo4j)
            self.context.trigger('filesystem_capture_end', root=root_inode)

    def walk_count(self, node):
        self.total_entries += 1
        if self.gfs.is_dir(str(node)):
            entries = self.list_entries(node)
            for entry in entries:
                subnode_abs = node / entry
                self.walk_count(subnode_abs)

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
        self.context.trigger('filesystem_new_inode', inode=inode)
        # download and execute trigger on local file
        if InodeType(inode.inode_type) == InodeType.REG:
            self.context.trigger('filesystem_new_file', inode=inode)
        # walk
        if self.gfs.is_dir(str(node)):
            entries = self.list_entries(node)
            for entry in entries:
                subnode_abs = node / entry
                child_inode = self.walk_capture(subnode_abs)
                self.context.trigger('filesystem_new_child_inode', inode=inode, child=child_inode)
                # cleanup inode related resources
                child_inode.close()

        self.context.trigger('filesystem_end_children', inode=inode)
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


class Neo4jFilesystemHook(Hook):

    def __init__(self, parameters):
        super().__init__(parameters)
        # config
        self.graph = self.configuration['graph']
        self.root_g_inode = None
        self.tx = None
        self.fs = {}
        self.context.subscribe('filesystem_capture_begin', self.fs_capture_begin)
        self.context.subscribe('filesystem_capture_end', self.fs_capture_end)
        self.context.subscribe('filesystem_new_inode', self.process_new_inode)
        self.context.subscribe('filesystem_new_file_mime', self.process_new_file_mime)
        self.context.subscribe('filesystem_new_child_inode', self.process_new_child)
        self.context.subscribe('filesystem_end_children', self.process_end_children)
        self.context.subscribe('security_checksec_bin', self.process_checksec_file)

    def fs_capture_begin(self, event):
        # start py2neo transaction
        # call self.graph.create() for each inode would be way too slow
        self.tx = self.graph.begin()

    def fs_capture_end(self, event):
        # commit transaction
        self.tx.commit()
        self.context.trigger('neo4jfs_capture_end', root=self.root_g_inode)

    def process_new_inode(self, event):
        inode = event.inode
        g_inode = GraphInode(inode)
        self.fs[str(inode.path)] = g_inode
        if inode.path == Path('/'):
            self.root_g_inode = g_inode

    def process_new_file_mime(self, event):
        inode = event.inode
        mime = event.mime
        self.fs[str(inode.path)].mime_type = mime

    def process_new_child(self, event):
        inode = event.inode
        child = event.child
        g_child_inode = GraphInode(child)
        self.fs[str(inode.path)].children.add(g_child_inode)
        self.tx.create(g_child_inode)

    def process_end_children(self, event):
        inode = event.inode
        key = str(inode.path)
        self.tx.push(self.fs[key])
        del self.fs[key]

    def process_checksec_file(self, event):
        inode = event.inode
        checksec_file = event.checksec_file
        self.fs[str(inode.path)].checksec = True
        self.fs[str(inode.path)].relro = checksec_file.relro
        self.fs[str(inode.path)].canary = checksec_file.canary
        self.fs[str(inode.path)].nx = checksec_file.nx
        self.fs[str(inode.path)].pie = checksec_file.pie
        self.fs[str(inode.path)].rpath = checksec_file.rpath
        self.fs[str(inode.path)].runpath = checksec_file.runpath
        self.fs[str(inode.path)].symtables = checksec_file.symtables
        self.fs[str(inode.path)].fortify_source = checksec_file.fortify_source
        self.fs[str(inode.path)].fortified = checksec_file.fortified
        self.fs[str(inode.path)].fortifyable = checksec_file.fortifyable


class GitFilesystemHook(Hook):

    def __init__(self, parameters):
        super().__init__(parameters)
        self.repo_path = Path(self.configuration['repo'])
        self.commit_message = self.configuration.get('commit_message', None)
        self.file_content = self.configuration.get('file_content', False)
        self.repo = Repo(str(self.repo_path))
        # repo must be clean
        if self.repo.is_dirty():
            raise RuntimeError("Repository is dirty. Aborting.")

        if self.file_content:
            self.context.subscribe('filesystem_new_file', self.process_new_file)
        else:
            # only capture filesystem tree
            self.context.subscribe('filesystem_new_inode', self.process_new_inode)
        self.context.subscribe('filesystem_capture_end', self.fs_capture_end)

    def process_new_inode(self, event):
        inode = event.inode
        filepath = self.repo_path / inode.path.relative_to('/')
        # test if exists
        if not filepath.exists():
            if InodeType(inode.inode_type) == InodeType.DIR:
                filepath.mkdir(parents=True, exist_ok=True)
            else:
                # everything else is treated as file
                filepath.parent.mkdir(parents=True, exist_ok=True)
                filepath.touch()

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
        # add all files
        self.logger.info('Adding all files in the working tree')
        self.repo.git.add('-A')
        # commit
        message = self.configuration['domain_name']
        # if exists and not empty
        if self.commit_message is not None and self.commit_message:
            message = self.commit_message
        self.logger.info('Creating new commit \'%s\'', message)
        self.repo.git.commit('-m', message)
