from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

ENGINE = create_engine('postgresql://postgres:6040@localhost/fast_7', echo=True)
Base = declarative_base()
session = sessionmaker()
