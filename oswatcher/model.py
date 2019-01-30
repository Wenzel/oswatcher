import stat
import subprocess
import re
from enum import Enum
from contextlib import contextmanager
from tempfile import NamedTemporaryFile

from py2neo.ogm import GraphObject, Property, RelatedTo, RelatedFrom


@contextmanager
def guest_local_file(gfs, remote_file):
    with NamedTemporaryFile() as temp:
        gfs.download(remote_file, temp.name)
        yield temp.name

class OS(GraphObject):

    def __init__(self, name):
        super().__init__()
        self.name = name

    # properties
    name = Property()

    # relationships
    root_fileystem = RelatedTo("Inode", "OWNS_FILESYSTEM")
    syscall_tables = RelatedTo("SyscallTable", "OWNS_SYSCALL_TABLE")
    processes = RelatedTo("Process", "OWNS_PROCESS")


class InodeType(Enum):
    DIR  = stat.S_IFDIR
    CHR  = stat.S_IFCHR
    BLK  = stat.S_IFBLK
    REG  = stat.S_IFREG
    FIFO = stat.S_IFIFO
    LNK  = stat.S_IFLNK
    SOCK = stat.S_IFSOCK
    DOOR = stat.S_IFDOOR


class Inode(GraphObject):

    def __init__(self, guestfs, filepath, checksums):
        super().__init__()
        s_filepath = str(filepath)
        name = filepath.name
        # root ?
        if not name:
            name = filepath.anchor
        self.name = name
        if guestfs.is_file(s_filepath) and checksums:
            # checksums
            self.md5sum = guestfs.checksum('md5', s_filepath)
            self.sha1sum = guestfs.checksum('sha1', s_filepath)
            self.sha256sum = guestfs.checksum('sha256', s_filepath)
            self.sha512sum = guestfs.checksum('sha512', s_filepath)

        # l -> if symbolic link, returns info about the link itself
        file_stat = guestfs.lstatns(s_filepath)
        self.size = file_stat['st_size']
        self.mode = stat.filemode(file_stat['st_mode'])
        self.inode_type = InodeType(stat.S_IFMT(file_stat['st_mode'])).value
        self.file_type = guestfs.file(s_filepath)
        if InodeType(self.inode_type) == InodeType.REG:
            self.mime_type = guestfs.command(['file', '-bi', s_filepath]).rstrip()
            if re.match('.*application/x-(((pie-)?executable)|sharedlib).*', self.mime_type):
                # apparently libguestfs raises a RuntimeError when
                # running ldd on some binaries, for no clear reason
                # catching the error and silently passing for now
                try:
                    ldd_output = [l.strip() for l in guestfs.command_lines(['ldd', s_filepath])]
                except RuntimeError:
                    print("{}: ldd failed ! (libguestfs buf ?)".format(s_filepath))
                    pass
                else:
                    self.dynlibs = []
                    for lib in ldd_output:
                        lib_path = None
                        m = re.match('(?P<lib_path>/.*) (.*)', lib)
                        if m:
                            lib_path = m.group('lib_path')
                        m = re.match('.* => (?P<lib_path>/.*) (.*)', lib)
                        if m:
                            lib_path = m.group('lib_path')
                        # linux-gate
                        m = re.match('(?P<lib_path>.*) =>  (.*)', lib)
                        if m:
                            lib_path = m.group('lib_path')
                        self.dynlibs.append(lib_path)

            # if file needs to be downloaded on host temporarily
            # with guest_local_file(guestfs, s_filepath) as local_file:


    # properties
    name = Property()
    size = Property()
    md5sum = Property()
    sha1sum = Property()
    sha256sum = Property()
    sha512sum = Property()
    inode_type = Property()
    file_type = Property()
    mime_type = Property()

    # relationships
    children = RelatedTo("Inode", "HAS_CHILD")
    owned_by = RelatedTo("OS", "OWNED_BY")
    dependencies = RelatedTo("Inode", "DYNLINK_WITH")


class SyscallTable(GraphObject):

    def __init__(self, index, name):
        super().__init__()
        self.index = index
        self.name = name

    # properties
    index = Property()
    name = Property()

    syscalls = RelatedTo("Syscall", "OWNS_SYSCALL")
    owned_by = RelatedTo("OS", "OWNED_BY")


class Syscall(GraphObject):

    def __init__(self, index, name, address):
        super().__init__()
        self.index = index
        self.name = name
        self.address = address

    # properties
    table = Property()
    index = Property()
    name = Property()
    address = Property()

    owned_by = RelatedTo("SyscallTable", "OWNED_BY")


class Process(GraphObject):

    def __init__(self, process_addr, name, pid, ppid, thread_count,
                 handle_count, wow64):
        super().__init__()
        self.process_addr = process_addr
        self.name = name
        self.pid = pid
        self.ppid = ppid
        self.thread_count = thread_count
        self.handle_count = handle_count
        self.wow64 = wow64

    # properties
    process_addr = Property()
    name = Property()
    pid = Property()
    ppid = Property()
    thread_count = Property()
    handle_count = Property()
    wow64 = Property()

    owned_by = RelatedTo("OS", "OWNED_BY")
