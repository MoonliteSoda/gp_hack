from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from rest.models.login_data import LoginData
from rest.models.user_response_data import UserResponseData
from service.auth_service import AuthService
from utils.logger import get_logger
from rest.models.user_data import UserData
from rest.models.token_data import TokenData

log = get_logger("AuthEndpoint")
router = APIRouter()


@router.post(
    "/api/auth/register",
    responses={
        200: {"model": UserResponseData, "description": "Successful response"},
    },
    tags=["Auth"],
    response_model_by_alias=True,
)
async def register(user_data: UserData, auth_service: AuthService = Depends()):
    log.info(f"Register request email: {user_data.email}",  extra={"email": user_data.email})
    await auth_service.register_user(user_data)
    log.info(f"Send link on email: {user_data.email}", exc_info={"email": user_data.email})
    return None


@router.post(
    "/api/auth/login",
    responses={
        200: {"model": TokenData, "description": "Successful response"},
    },
    tags=["Auth"],
    response_model_by_alias=True,
)
async def login(login_data: LoginData, auth_service: AuthService = Depends()) -> TokenData:
    pass
    # log.info("Login request received")
    # result = await auth_service.login(login_data)
    # log.info("Login request processed successfully")
    # return result


@router.get(
    "/api/auth/me",
    responses={
        200: {"model": UserResponseData, "description": "Successful response"},
    },
    tags=["Auth"],
    response_model_by_alias=True,
)
async def get_current_user(current_user: UserData = Depends()) -> UserResponseData:
    pass
    # log.info(f"Get current user request for {current_user.email}")
    # return UserResponseData(email=current_user.email, name=current_user.name)
