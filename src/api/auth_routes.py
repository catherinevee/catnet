from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import Dict, Any

from ..db.session import get_db
from ..auth.authentication import AuthenticationService
from ..auth.dependencies import get_current_user
from ..db.models import User

router = APIRouter()

@router.post("/login")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    auth_service = AuthenticationService(db)

    user, error = await auth_service.authenticate_user(
        username=form_data.username,
        password=form_data.password,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent")
    )

    if error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error
        )

    return await auth_service.create_session(
        user,
        request.client.host,
        request.headers.get("user-agent")
    )

@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    auth_service = AuthenticationService(db)
    await auth_service.logout(
        request.headers.get("authorization", "").replace("Bearer ", ""),
        str(current_user.id),
        request.client.host
    )
    return {"message": "Logged out successfully"}

@router.get("/me")
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    return {
        "id": str(current_user.id),
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role.value,
        "mfa_enabled": current_user.mfa_enabled
    }