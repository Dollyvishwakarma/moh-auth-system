from fastapi import APIRouter, Depends

from app.core.security import (
    get_current_user,
    get_current_verified_user,
)
from app.models.user import User
from app.schemas.user import UserOut

router = APIRouter()


@router.get("/me", response_model=UserOut)
def read_me(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/premium")
def premium_route(
    current_user: User = Depends(get_current_verified_user),
):
    return {
        "message": f"Welcome to premium content, {current_user.username}!",
        "premium": True,
    }
