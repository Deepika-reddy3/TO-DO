
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from bson import ObjectId

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TodoBase(BaseModel):
    title: str
    completed: bool = False
    due: Optional[str] = None  # or datetime if you're parsing
    priority: Optional[str] = "medium"

class TodoUpdate(BaseModel):
    title: Optional[str] = None
    completed: Optional[bool] = None
    priority: Optional[str] = None
    due: Optional[str] = None

class TodoResponse(TodoBase):
    id: str = Field(..., alias="_id")
