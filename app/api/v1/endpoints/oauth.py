from typing import Optional

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.auth.oauth_handler import oauth
from app.core.config import settings
from app.database.session import get_db
from app.models.user import User
from app.services import auth_service

router = APIRouter()


def _get_or_create_oauth_user(
    db: Session,
    provider: str,
    provider_id: str,
    email: str,
    name: Optional[str],
) -> User:
    user = (
        db.query(User)
        .filter(
            User.provider == provider,
            User.provider_id == provider_id,
        )
        .first()
    )
    if user:
        return user

    user = db.query(User).filter(User.email == email).first()
    if user:
        user.provider = provider
        user.provider_id = provider_id
        user.is_verified = True
        db.commit()
        db.refresh(user)
        return user

    username_base = email.split("@")[0]
    username = username_base
    i = 1
    while db.query(User).filter(User.username == username).first():
        username = f"{username_base}{i}"
        i += 1

    user = User(
        email=email,
        username=username,
        full_name=name,
        provider=provider,
        provider_id=provider_id,
        is_verified=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.get("/google/login")
async def google_login(request: Request):
    redirect_uri = f"{settings.BACKEND_URL}/api/v1/oauth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/google/callback")
async def google_callback(
    request: Request,
    db: Session = Depends(get_db),
):
    token = await oauth.google.authorize_access_token(request)
    userinfo = token.get("userinfo") or await oauth.google.parse_id_token(
        request, token
    )
    user = _get_or_create_oauth_user(
        db,
        "google",
        str(userinfo["sub"]),
        userinfo["email"],
        userinfo.get("name"),
    )
    access, refresh = auth_service.issue_tokens(db, user)
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
    }


@router.get("/github/login")
async def github_login(request: Request):
    redirect_uri = f"{settings.BACKEND_URL}/api/v1/oauth/github/callback"
    return await oauth.github.authorize_redirect(request, redirect_uri)


@router.get("/github/callback")
async def github_callback(
    request: Request,
    db: Session = Depends(get_db),
):
    token = await oauth.github.authorize_access_token(request)
    resp = await oauth.github.get("user", token=token)
    profile = resp.json()

    email = profile.get("email")
    if not email:
        er = await oauth.github.get("user/emails", token=token)
        emails = er.json()
        email = next(
            (e["email"] for e in emails if e.get("primary")),
            emails[0]["email"],
        )

    user = _get_or_create_oauth_user(
        db,
        "github",
        str(profile["id"]),
        email,
        profile.get("name") or profile.get("login"),
    )
    access, refresh = auth_service.issue_tokens(db, user)
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
    }
