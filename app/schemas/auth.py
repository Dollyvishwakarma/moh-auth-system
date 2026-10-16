from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class OTPRequest(BaseModel):
    email: EmailStr
    purpose: str = Field(
        default="login",
        pattern="^(login|email_verify|password_reset)$",
    )


class OTPVerify(BaseModel):
    email: EmailStr
    code: str = Field(min_length=4, max_length=8)


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    email: EmailStr
    code: str = Field(min_length=4, max_length=8)
    new_password: str = Field(min_length=8)


class MessageResponse(BaseModel):
    message: str
