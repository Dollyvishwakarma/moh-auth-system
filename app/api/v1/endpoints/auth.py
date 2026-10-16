from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.auth.password import hash_password
from app.database.session import get_db
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    MessageResponse,
    OTPRequest,
    OTPVerify,
    PasswordResetConfirm,
    PasswordResetRequest,
)
from app.schemas.token import Token, TokenRefreshRequest
from app.schemas.user import UserCreate, UserOut
from app.services import auth_service, email_service, otp_service

router = APIRouter()


@router.post("/register", response_model=UserOut, status_code=201)
def register(data: UserCreate, db: Session = Depends(get_db)):
    user = auth_service.register_user(db, data)
    code = otp_service.generate_otp(db, user.id, purpose="email_verify")
    email_service.send_email(
        user.email,
        "Verify your email",
        f"Your OTP code: {code}",
    )
    return user


@router.post("/login", response_model=Token)
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = auth_service.authenticate_user(db, form.username, form.password)
    access, refresh = auth_service.issue_tokens(db, user)
    return Token(access_token=access, refresh_token=refresh)


@router.post("/login/json", response_model=Token)
def login_json(data: LoginRequest, db: Session = Depends(get_db)):
    user = auth_service.authenticate_user(db, data.email, data.password)
    access, refresh = auth_service.issue_tokens(db, user)
    return Token(access_token=access, refresh_token=refresh)


@router.post("/refresh", response_model=Token)
def refresh(data: TokenRefreshRequest, db: Session = Depends(get_db)):
    access, refresh = auth_service.rotate_refresh_token(db, data.refresh_token)
    return Token(access_token=access, refresh_token=refresh)


@router.post("/logout", response_model=MessageResponse)
def logout(data: TokenRefreshRequest, db: Session = Depends(get_db)):
    auth_service.logout_user(db, data.refresh_token)
    return MessageResponse(message="Logged out successfully")


@router.post("/otp/request", response_model=MessageResponse)
def request_otp(data: OTPRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        return MessageResponse(
            message="If the email exists, an OTP was sent"
        )
    code = otp_service.generate_otp(db, user.id, purpose=data.purpose)
    email_service.send_email(
        user.email,
        f"Your {data.purpose} OTP",
        f"Code: {code}",
    )
    return MessageResponse(message="OTP sent")


@router.post("/otp/verify", response_model=Token)
def verify_otp_login(data: OTPVerify, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    otp_service.verify_otp(db, user.id, data.code, "login")
    access, refresh = auth_service.issue_tokens(db, user)
    return Token(access_token=access, refresh_token=refresh)


@router.post("/verify-email", response_model=MessageResponse)
def verify_email(data: OTPVerify, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    otp_service.verify_otp(db, user.id, data.code, "email_verify")
    user.is_verified = True
    db.commit()
    return MessageResponse(message="Email verified successfully")


@router.post("/password-reset/request", response_model=MessageResponse)
def password_reset_request(
    data: PasswordResetRequest,
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == data.email).first()
    if user:
        code = otp_service.generate_otp(
            db, user.id, purpose="password_reset"
        )
        email_service.send_email(
            user.email,
            "Password Reset Code",
            f"Code: {code}",
        )
    return MessageResponse(
        message="If the email exists, a reset code was sent"
    )


@router.post("/password-reset/confirm", response_model=MessageResponse)
def password_reset_confirm(
    data: PasswordResetConfirm,
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    otp_service.verify_otp(db, user.id, data.code, "password_reset")
    user.hashed_password = hash_password(data.new_password)
    db.commit()
    return MessageResponse(message="Password reset successful")
