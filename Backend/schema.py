"""All shche of backend"""
from pydantic import BaseModel

class UserBase(BaseModel):
    """Base for User schema"""
    username : str
    password : str

class UserCreated(UserBase):
    """Schema for user request"""
    pass

class UserResponse(BaseModel):
    """Schema of response to client"""
    id : str
    username : str
    class Config:
        from_attributes = True #เมื่อได้สิ่งที่จะ return จะแมปกับ Class นี้ก่อน
