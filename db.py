from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import config

# global
engine = create_engine('mysql+cymysql://{}:{}@{}/{}'.format(
    config.DB_USER,
    config.DB_PASS,
    config.DB_HOST,
    config.DB_NAME),
    encoding='utf-8')
Base = declarative_base(engine)
Session = sessionmaker(bind=engine)
session = Session()

class Filesystem(Base):
    __tablename__ = 'filesystem'
    __table_args__ = {'autoload':True}
