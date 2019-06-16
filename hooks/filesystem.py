# sys
import time
import subprocess
from tempfile import NamedTemporaryFile
from pathlib import Path
from contextlib import contextmanager

# local
from oswatcher.model import Inode, InodeType

# 3rd
import guestfs
from see import Hook


@contextmanager
def guestfs_instance(self):
    self.logger.info('Initializing libguestfs')
    self.gfs = guestfs.GuestFS(python_return_dict=True)
    # attach libvirt domain
    self.gfs.add_libvirt_dom(self.context.domain, readonly=True)
    self.logger.debug('Running libguestfs backend')
    self.gfs.launch()
    roots = self.gfs.inspect_os()
    if len(roots) == 0:
        raise RuntimeError('no operating system found')
    # use main filesystem
    root = roots[0]
    mps = self.gfs.inspect_get_mountpoints(root)
    self.logger.debug('Mounting filesystem')
    for mount_point, device in mps.items():
        self.gfs.mount_ro(device, mount_point)
    try:
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
        self.graph = self.configuration['graph']
        self.delete = self.configuration.get('delete', False)
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

    def capture_fs(self, event):
        with guestfs_instance(self) as gfs:
            # delete previous graph ?
            if self.delete:
                self.logger.info('Delete all nodes in graph')
                self.graph.delete_all()
            root = Path('/')
            if self.enumerate:
                self.logger.info('Enumerating entries')
                self.walk_count(root)
            self.logger.info('Capturing filesystem')
            self.time_last_update = time.time()
            # start py2neo transaction
            # call self.graph.create() for each inode would be way too slow
            self.tx = self.graph.begin()
            root_inode = self.walk_capture(root)
            # commit transaction
            self.tx.commit()
            # signal the operating system hook
            # that the FS has been inserted
            # and send it the root_inode to build the relationship
            self.context.trigger('filesystem_inserted', root=root_inode)

    def walk_count(self, node):
        self.total_entries += 1
        if self.gfs.is_dir(str(node)):
            entries = self.gfs.ls(str(node))
            for entry in entries:
                subnode_abs = node / entry
                self.walk_count(subnode_abs)

    def walk_capture(self, node):
        self.counter += 1
        # logging the progress ?
        if self.log_progress:
            self.update_log(node)
        # process current node
        inode = Inode(self.gfs, node, self.inode_checksums)
        # download and execute trigger on local file
        if InodeType(inode.inode_type) == InodeType.REG:
            with guest_local_file(self.gfs, str(node)) as local_file:
                self.context.trigger('filesystem_new_file', filepath=local_file, inode=inode)
        # walk
        if self.gfs.is_dir(str(node)):
            entries = self.gfs.ls(str(node))
            for entry in entries:
                subnode_abs = node / entry
                child_inode = self.walk_capture(subnode_abs)
                inode.children.add(child_inode)
        # update graph inode
        self.tx.create(inode)
        return inode

    def process_new_file(self, event):
        filepath = event.filepath
        inode = event.inode
        # determine MIME type and update inode
        inode.mime_type = subprocess.check_output(['file', '-bi', filepath]).decode().rstrip()
        self.context.trigger('filesystem_new_file_mime', filepath=filepath, inode=inode, mime=inode.mime_type)

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
