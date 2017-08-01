import os

from py2neo.ogm import GraphObject, Property, RelatedFrom, RelatedTo

class Inode(GraphObject):

    def __init__(self, guestfs, filepath):
        super().__init__()
        filename = os.path.basename(filepath)
        # root ?
        if not filename:
            filename = "/"
        self.filename = filename

    filename = Property()
    children = RelatedTo("Inode", "has_child")