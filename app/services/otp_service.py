import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.token import OTPCode


def generate_otp(
    db: Session,
    user_id: int,
    purpose: str = "login",
    length: int = 6,
    ttl_minutes: int = 10,
) -> str:
    code = "".join(str(secrets.randbelow(10)) for _ in range(length))
    expires = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
    otp = OTPCode(
        user_id=user_id,
        code=code,
        purpose=purpose,
        expires_at=expires,
    )
    db.add(otp)
    db.commit()
    return code


def verify_otp(db: Session, user_id: int, code: str, purpose: str) -> bool:
    otp = (
        db.query(OTPCode)
        .filter(
            OTPCode.user_id == user_id,
            OTPCode.code == code,
            OTPCode.purpose == purpose,
            OTPCode.used.is_(False),
        )
        .order_by(OTPCode.id.desc())
        .first()
    )
    if not otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    expires = otp.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="OTP expired")

    otp.used = True
    db.commit()
    return True
