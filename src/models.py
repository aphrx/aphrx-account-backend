from sqlalchemy import Column, Integer, String, DateTime, Boolean
from src.database import Base

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(255), nullable=False, unique=True)
    first_name = Column(String(255))
    last_name = Column(String(255))
    bio = Column(String(255))
    avatar_url = Column(String(255))


class UserCreds(User):
    password = Column(String(255), nullable=False)

class Profile(Base):
    __tablename__ = 'profile'

    id = Column(Integer, primary_key=True)
    username = Column(String)
    section = Column(String)
    title = Column(String)
    body = Column(String)
    image_url = Column(String)
    destination_url = Column(String)
    priority = Column(Integer)

class App(Base):
    __tablename__ = 'apps'

    id = Column(Integer, primary_key=True)

    title = Column(String)
    body = Column(String)
    image_url = Column(String)
    destination_url = Column(String)
    availability = Column(Boolean)
    availability_reason = Column(String)

class Setting(Base):
    __tablename__ = 'settings'

    id = Column(Integer, primary_key=True)

    title = Column(String)
    status = Column(String)
    function = Column(String)
    username = Column(String)