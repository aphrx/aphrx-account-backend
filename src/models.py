from sqlalchemy import Column, Integer, String, DateTime, Boolean
from src.database import Base

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(255), nullable=False, unique=True)

class UserCreds(User):
    password = Column(String(255), nullable=False)

class Profile(Base):
    __tablename__ = 'profile'

    id = Column(Integer, primary_key=True)
    