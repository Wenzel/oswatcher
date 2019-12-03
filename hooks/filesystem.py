# sys
import time
import stat
import subprocess
from enum import Enum
from tempfile import NamedTemporaryFile
from pathlib import Path
from contextlib import contextmanager
from dataclasses import dataclass

# local
from oswatcher.model import GraphInode

# 3rd
import guestfs
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


@dataclass
class Inode:
    name: str
    path: Path
    status: dict
    size: int
    mode: dict
    inode_type: InodeType
    file_type: str


@contextmanager
def guestfs_instance(self):
    self.logger.info('Initializing libguestfs')
    self.gfs = guestfs.GuestFS(python_return_dict=True)
    # attach libvirt domain
    self.gfs.add_libvirt_dom(self.context.domain, readonly=True)
    self.logger.debug('Running libguestfs backend')
    self.gfs.launch()
    try:
        partitions = self.gfs.list_partitions()
        if len(partitions) == 0:
            raise RuntimeError('no partitions found')
        # use first partition
        # TODO: have a better detection of the main filesystem
        main_partition = partitions[0]
        self.logger.debug('Mounting filesystem')
        self.gfs.mount_ro(main_partition, '/')
        yield self.gfs
    finally:
        # shutdown
        self.logger.debug('shutdown libguestfs')
        self.gfs.umount_all()
        self.gfs.shutdown()


@contextmanager
def guest_local_file(gfs, remote_file):
    with NamedTemporaryFile() as temp:
        gfs.download(remote_file, temp.name)
        yield temp.name


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
        self.context.subscribe('filesystem_new_file', self.process_new_file)

    def list_entries(self, node):
        # assume that node is a directory
        # workaround bug in libguestfs: https://bugzilla.redhat.com/show_bug.cgi?id=1778962
        try:
            return self.gfs.ls(str(node))
        except UnicodeDecodeError:
            self.logger.warning("Cannot list entries of %s directory", str(node))
            return []

    def capture_fs(self, event):
        with guestfs_instance(self) as gfs:
            root = Path('/')
            if self.enumerate:
                self.logger.info('Enumerating entries')
                self.walk_count(root)
            self.logger.info('Capturing filesystem')
            self.time_last_update = time.time()

            self.context.trigger('filesystem_capture_begin')
            root_inode = self.walk_capture(root)
            # signal the operating system hook
            # that the FS has been inserted
            # and send it the root_inode to build the relationship
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
        # convert Path to string
        name = node.name
        # root
        if not name:
            name = node.anchor
        s_filepath = str(node)
        # l -> if symbolic link, returns info about the link itself
        file_stat = self.gfs.lstatns(s_filepath)
        size = file_stat['st_size']
        mode = stat.filemode(file_stat['st_mode'])
        inode_type = InodeType(stat.S_IFMT(file_stat['st_mode'])).value
        file_type = self.gfs.file(s_filepath)

        inode = Inode(name, node, file_stat, size, mode, inode_type, file_type)
        self.context.trigger('filesystem_new_inode', inode=inode)
        # download and execute trigger on local file
        if InodeType(inode.inode_type) == InodeType.REG:
            with guest_local_file(self.gfs, str(node)) as local_file:
                self.context.trigger('filesystem_new_file', filepath=local_file, inode=inode)
        # walk
        if self.gfs.is_dir(str(node)):
            entries = self.list_entries(node)
            for entry in entries:
                subnode_abs = node / entry
                child_inode = self.walk_capture(subnode_abs)
                self.context.trigger('filesystem_new_child_inode', inode=inode, child=child_inode)

        self.context.trigger('filesystem_end_children', inode=inode)
        # update graph inode
        return inode

    def process_new_file(self, event):
        filepath = event.filepath
        inode = event.inode
        # determine MIME type
        mime_type = subprocess.check_output(['file', '-bi', filepath]).decode().rstrip()
        self.context.trigger('filesystem_new_file_mime', filepath=filepath, inode=inode, mime=mime_type)

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
        key = str(inode.path)
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
        self.repo = Repo(str(self.repo_path))
        # repo must be clean
        if self.repo.is_dirty():
            raise RuntimeError("Repository is dirty. Aborting.")

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
        # git add
        self.repo.git.add(str(filepath))

    def fs_capture_end(self, event):
        # commit
        domain_name = self.configuration['domain_name']
        self.repo.git.commit('-m', domain_name)