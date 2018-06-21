# sys
from see import Hook

# local
from oswatcher.utils import get_hard_disk

# 3rd
import guestfs

class FilesystemHook(Hook):

    def __init__(self, parameters):
        super().__init__(parameters)
        self.graph = self.configuration['graph']
        self.context.subscribe('offline', self.capture_fs)

    def init_libguestfs(self):
        self.logger.info('initializing libguestfs')
        qcow_path = get_hard_disk(self.context.domain)
        self.logger.debug('hard disk path: %s', qcow_path)
        self.gfs = guestfs.GuestFS(python_return_dict=True)
        # attach drive
        self.gfs.add_drive_opts(qcow_path, readonly=1)
        self.logger.debug('running libguestfs backend')
        self.gfs.launch()
        roots = self.gfs.inspect_os()
        if len(roots) == 0:
            raise RuntimeError('no operating system found')
        # use main filesystem
        root = roots[0]
        mps = self.gfs.inspect_get_mountpoints(root)
        self.logger.debug('mounting filesystem')
        for mount_point, device in mps.items():
            self.gfs.mount_ro(device, mount_point)

    def capture_fs(self, event):
        self.init_libguestfs()
        print(self.graph)