from pydantic import BaseModel
from typing import Optional


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: Optional[str] = "user"  # VULNERABILITY: Mass assignment of role


class IssueCreate(BaseModel):
    title: str
    description: str
    status: Optional[str] = "open"
    owner_id: Optional[int] = None


class LoginModel(BaseModel):
    username: str
    password: str
