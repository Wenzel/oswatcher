from py2neo.ogm import GraphObject, Property, RelatedTo, RelatedFrom

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
        stat = guestfs.lstatns(s_filepath)
        self.size = stat['st_size']


    # properties
    name = Property()
    size = Property()
    md5sum = Property()
    sha1sum = Property()
    sha256sum = Property()
    sha512sum = Property()


    # relationships
    children = RelatedTo("Inode", "HAS_CHILD")
    owned_by = RelatedTo("OS", "OWNED_BY")


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
