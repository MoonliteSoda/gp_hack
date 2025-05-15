from fastapi import APIRouter, Depends, HTTPException, status

from rest.models.login_data import LoginData
from rest.models.user_response_data import UserResponseData
from rest.models.login_response import LoginResponse
from service.auth_service import AuthService
from utils.logger import get_logger
from rest.models.user_data import UserData
from rest.models.token_data import TokenData


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
    log.info(f"Register request email: {user_data.email}",  extra={"email": user_data.email})
    await auth_service.register_user(user_data)
    log.info(f"Send link on email: {user_data.email}", exc_info={"email": user_data.email})
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
    try:
        response = await auth_service.authenticate_user(login_data)
        if response:
            log.info(f"Успешная авторизация: {login_data.email}")
            return response
        log.warning(f"Ошибка при сравнении: {login_data.email}")
        return LoginResponse(message="Неверный email или пароль")
    except Exception as e:
        log.error(f"Ошибка авторизации {login_data.email}, error: {str(e)}")
        raise HTTPException(status_code=404, detail=str(e))


@router.get(
    "/api/auth/me",
    responses={
        200: {"model": UserResponseData, "description": "Successful response"},
    },
    tags=["Auth"],
    response_model_by_alias=True,
)
@auth_service.require_api_auth
async def get_current_user(current_user: UserData = Depends()) -> :
    # log.info(f"Get current user request for {current_user.email}")
    # return UserResponseData(email=current_user.email, name=current_user.name)
