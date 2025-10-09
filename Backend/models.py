from sqlalchemy import Column, String
from sqlalchemy.dialects.postgresql import UUID
from .database import Base
import uuid

class User(Base): #Inherit จาก Base ของ Database เพื่อแมปให้ตรงกับ Table ของ Database
    """For create or connect to User table"""
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, nullable=True)

class Bin(Base):
    """For create or connect to Bin table"""
    __tablename__ = "bins"
    bin_id = Column(String, unique=True, nullable=True, primary_key=True)
    status = Column(String, nullable=False)

class UserBin(Base):
    """For create or connect to UserBin table"""
    __tablename__ = "user_bins"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), default=uuid.uuid4)
    bin_id = Column(String, nullable=True)
