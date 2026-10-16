import re
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

PASSWORD_RE_UPPER = re.compile(r"[A-Z]")
PASSWORD_RE_LOWER = re.compile(r"[a-z]")
PASSWORD_RE_DIGIT = re.compile(r"\d")
PASSWORD_RE_SPECIAL = re.compile(r"[!@#$%^&*(),.?\":{}|<>_\-+=]")


class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    full_name: Optional[str] = Field(default=None, max_length=120)


class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not PASSWORD_RE_UPPER.search(v):
            raise ValueError("Password must contain an uppercase letter")
        if not PASSWORD_RE_LOWER.search(v):
            raise ValueError("Password must contain a lowercase letter")
        if not PASSWORD_RE_DIGIT.search(v):
            raise ValueError("Password must contain a digit")
        if not PASSWORD_RE_SPECIAL.search(v):
            raise ValueError("Password must contain a special character")
        return v


class UserOut(UserBase):
    id: int
    is_active: bool
    is_verified: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
