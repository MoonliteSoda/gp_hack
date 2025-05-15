from fastapi import APIRouter, Depends, HTTPException, status

from rest.models.login_data import LoginData
from rest.models.user_response_data import UserResponseData
from rest.models.login_response import LoginResponse
from service.auth_service import AuthService
from utils.logger import get_logger
from rest.models.user_data import UserData
from rest.models.token_data import TokenData
from dao.account import Account

log = get_logger("AuthEndpoint")

router = APIRouter()

auth_service = AuthService()


@router.post(
    "/api/auth/register",
    responses={
        200: {"model": UserResponseData, "description": "Successful response"},
    },
    tags=["Auth"],
    response_model_by_alias=True,
)
async def register(user_data: UserData, auth_service: AuthService = Depends())->str:
    await auth_service.register_user(user_data)
    log.info(f"Register request email: {user_data.email} finish;",  extra={"email": user_data.email})
    return "Регистрация прошла успешно!"


@router.post(
    "/api/auth/login",
    responses={
        200: {"model": TokenData, "description": "Successful response"},
    },
    tags=["Auth"],
    response_model_by_alias=True,
)
async def login(login_data: LoginData, auth_service: AuthService = Depends()) -> LoginResponse | str:
    log.info(f"Login attempt for email: {login_data.email}")
    response = await auth_service.authenticate_user(login_data)
    return response


@router.get(
    "/api/auth/me",
    responses={
        200: {"model": UserResponseData, "description": "Successful response"},
    },
    tags=["Auth"],
    response_model_by_alias=True,
)
@auth_service.require_api_auth()
async def get_current_user(current_user=Depends(auth_service.get_user_from_token)) -> UserResponseData:
    """Возвращает данные текущего пользователя."""
    return UserResponseData(
        id=current_user.id,
        email=current_user.email,
        name=current_user.name,
        role=current_user.role
    )

