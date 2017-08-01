from py2neo.ogm import GraphObject, Property, RelatedTo

class Inode(GraphObject):

    def __init__(self, guestfs, filepath):
        super().__init__()
        name = filepath.name
        # root ?
        if not name:
            name = filepath.anchor
        self.filename = name

    filename = Property()
    children = RelatedTo("Inode", "has_child")