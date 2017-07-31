from py2neo.ogm import GraphObject, Property, RelatedFrom, RelatedTo

class Inode(GraphObject):

    filename = Property()
    children = RelatedTo("Inode", "has_child")