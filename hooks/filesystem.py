# sys
import time
from pathlib import Path

# local
from oswatcher.utils import get_hard_disk
from oswatcher.model import Inode

# 3rd
import guestfs
from see import Hook

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

        self.counter = 0
        self.total_entries = 0
        self.time_last_update = 0
        self.context.subscribe('offline', self.capture_fs)

    def init_libguestfs(self):
        self.logger.info('Initializing libguestfs')
        qcow_path = get_hard_disk(self.context.domain)
        self.logger.debug('Hard disk path: %s', qcow_path)
        self.gfs = guestfs.GuestFS(python_return_dict=True)
        # attach drive
        self.gfs.add_drive_opts(qcow_path, readonly=1)
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

    def capture_fs(self, event):
        self.init_libguestfs()
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
        self.walk_capture(root)

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
        inode = Inode(self.gfs, node, self.inode_checksums)
        if self.gfs.is_dir(str(node)):
            entries = self.gfs.ls(str(node))
            for entry in entries:
                subnode_abs = node / entry
                child_inode = self.walk_capture(subnode_abs)
                inode.children.add(child_inode)

        self.graph.create(inode)
        return inode

    def update_log(self, node):
        delta = time.time() - self.time_last_update
        if delta > self.log_progress_delay:
            perc = round(self.counter * 100 / self.total_entries, 1)
            self.logger.info("[{} %] {}".format(perc, node))
            # reset
            self.time_last_update = time.time()