from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import config

# global
engine = create_engine('postgres://{}:{}@{}/{}'.format(
    config.DB_USER,
    config.DB_PASS,
    config.DB_HOST,
    config.DB_NAME),
    encoding='utf-8')
Base = declarative_base(engine)

class OS(Base):
    __tablename__ = 'os'
    __table_args__ = {'autoload':True}

class Filesystem(Base):
    __tablename__ = 'filesystem'
    __table_args__ = {'autoload':True}

class Inode(Base):
    __tablename__ = 'inode'
    __table_args__ = {'autoload':True}

class OSWatcherDB:

    def __init__(self, vm_name):
        self.vm_name = vm_name
        Session = sessionmaker(bind=engine)
        self.session = Session()
        self.cache_path_ids = []
        # insert vm_name
        os = OS(vm_name)
        self.session.add(os)
        self.session.commit()
        # get vm_id
        self.vm_id = os.id

    def clear_old(self):
        # try to get alraedy existing vmid
        try:
            os_obj = self.session.query(OS).filter(OS.vm_name == self.vm_name).all()[0]
        else:
            vm_id = os_obj.vm_id
            logging.info('Clearing Inode Table')
            # clear Inode
            for inode_obj in self.session.query(Inode).filter(Inode.vm_id == vm_id):
                self.session.delete(inode_obj)
            logging.info('Clearing Filesystem Table')
            # clear Filesystem
            for fs_obj in self.session.query(Filesystem).filter(Filesystem.vm_id == vm_id):
                self.session.delete(fs_obj)
            logging.info('Clearing OS Table')
            # clear OS
            for os_obj in self.session.query(OS).filter(OS.id == vm_id):
                self.session.delete(fs_obj)
        except IndexError as e:
            logging.info('Not already existing')
            return

    def capture(self, node):
        path_components = []
        # decompose path
        path = node
        while path != '/':
            # get up
            path = os.path.dirname(path)
            # insert new path component
            component = os.path.basename(path)
            # basename on '/' returns an empty string
            # we have to set it to the root entry manually
            if not component:
                component = '/'
            path_components.append(component)
        # ['c', 'b', 'a'] => ['a', 'b', 'c']
        path_components.reverse()
        # print(path_components)
        # print(self.cache_path_ids)
        path_ids = []
        # found each parent dir
        for i, component in enumerate(path_components):
            # try cache
            try:
                cache_entry = self.cache_path_ids[i]
                # cache entry is tuple
                # tuple ("dir", id)
                component_id = cache_entry[1]
                if cache_entry[0] == component:
                    # print('found {} in cache'.format(component))
                    # we found an id in the cache !
                    path_ids.append(component_id)
                else:
                    # print('invalidate cache')
                    # delete element starting from index i to the end
                    del self.cache_path_ids[i:]
                    # query for ID
                    fs_obj = db.session.query(db.Filesystem).filter(db.Filesystem.filename == component, db.Filesystem.path.contains(path_ids)).all()[0]
                    # append id to path_ids
                    path_ids.append(fs_obj.inode)
                    # append new cache entry
                    cache_entry = (component, fs_obj.id)
                    self.cache_path_ids.append(cache_entry)

            except IndexError:
                # print("IndexError {}, outside of cache".format(i))
                # query for ID
                fs_obj = db.session.query(db.Filesystem).filter(db.Filesystem.filename == component, db.Filesystem.path.contains(path_ids)).all()[0]
                # append id to path_ids
                path_ids.append(fs_obj.inode)
                # append new cache entry
                cache_entry = (component, fs_obj.inode)
                self.cache_path_ids.append(cache_entry)

        # root ?
        name = os.path.basename(node)
        if name == '':
            name = '/'
        trans = insert(db.Filesystem)
        trans.execute(path=path_ids, name=name)














