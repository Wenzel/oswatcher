import stat
from enum import Enum
from uuid import uuid4

from py2neo.ogm import GraphObject, Property, RelatedTo


class OSType(Enum):
    Linux = 1
    Windows = 2


class InodeType(Enum):
    DIR = stat.S_IFDIR
    CHR = stat.S_IFCHR
    BLK = stat.S_IFBLK
    REG = stat.S_IFREG
    FIFO = stat.S_IFIFO
    LNK = stat.S_IFLNK
    SOCK = stat.S_IFSOCK
    DOOR = stat.S_IFDOOR


class OS(GraphObject):
    # properties
    id = Property()
    name = Property()
    type = Property()
    release_date = Property()

    # relationships
    root_filesystem = RelatedTo("GraphInode", "OWNS_FILESYSTEM")
    syscalls = RelatedTo("Syscall", "OWNS_SYSCALL")
    processes = RelatedTo("Process", "OWNS_PROCESS")

    def __init__(self, name, release_date=None):
        super().__init__()
        self.id = str(uuid4())
        self.name = name
        self.type = 'Unknown'
        self.release_date = release_date


class GraphInode(GraphObject):
    # properties
    name = Property()
    path = Property()
    size = Property()
    setuid = Property()
    setgid = Property()
    sticky = Property()
    md5sum = Property()
    sha1sum = Property()
    sha256sum = Property()
    sha512sum = Property()
    inode_type = Property()
    file_type = Property()
    mime_type = Property()
    checksec = Property()
    relro = Property()
    canary = Property()
    nx = Property()
    pie = Property()
    rpath = Property()
    runpath = Property()
    symbols = Property()
    fortify_source = Property()
    fortified = Property()
    fortifyable = Property()

    # relationships
    children = RelatedTo("GraphInode", "HAS_CHILD")
    owned_by = RelatedTo("OS", "OWNED_BY")

    def __init__(self, inode, os_type):
        super().__init__()
        self.name = inode.name
        self.path = inode.str_path
        self.size = inode.size
        self.mode = inode.mode
        self.inode_type = inode.inode_type_value
        if os_type == OSType.Linux:
            self.setuid = inode.is_setuid
            self.setgid = inode.is_setgid
            self.sticky = inode.is_sticky


class Syscall(GraphObject):
    # properties
    table = Property()
    index = Property()
    name = Property()
    address = Property()

    # relationships
    owned_by = RelatedTo("OS", "OWNED_BY")

    def __init__(self, table, index, name, address):
        super().__init__()
        self.table = table
        self.index = index
        self.name = name
        self.address = address


class Process(GraphObject):
    # properties
    name = Property()
    pid = Property()
    ppid = Property()
    thread_count = Property()
    handle_count = Property()
    wow64 = Property()

    # relationships
    owned_by = RelatedTo("OS", "OWNED_BY")

    def __init__(self, name, pid, ppid, thread_count,
                 handle_count, wow64):
        super().__init__()
        self.name = name
        self.pid = pid
        self.ppid = ppid
        self.thread_count = thread_count
        self.handle_count = handle_count
        self.wow64 = wow64
