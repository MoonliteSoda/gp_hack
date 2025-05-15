from datetime import datetime, timedelta
from typing import Optional, Callable, Any, Optional
from functools import wraps
import re

from sqlalchemy import select, Boolean
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy.future import select
from fastapi import HTTPException, Request, Response, status, Depends
from fastapi.responses import RedirectResponse

from rest.models.user_data import UserData
from rest.models.token_data import TokenData
from rest.models.login_data import LoginData
from rest.models.login_response import LoginResponse
from dao.account import Account, AccountStatus
from dao.base import session_factory, with_async_db_session
from utils.logger import get_logger
from utils.config import CONFIG


log = get_logger("AuthService")


#configAuth
SECRET_KEY = CONFIG.auth.SECRET_KEY
ALGORITHM = CONFIG.auth.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = CONFIG.auth.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = CONFIG.auth.REFRESH_TOKEN_EXPIRE_DAYS

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class AuthService:
    def __init__(self):
        pass

    @with_async_db_session
    async def register_user(self, user_data: UserData) -> Account:
        """Регистрирует нового пользователя,
        Args:
            user_data: Данные пользователя (email, password, name)

        Returns:
            Account: Созданный аккаунт пользователя

        Raises:
            ValueError: Если пользователь с таким email уже существует
            Exception: При других ошибках
        """
        existing_account = await self._get_account_by_email(user_data.email)
        if existing_account:
            log.warning(f"User with email {user_data.email} already exists")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Пользователь с таким email уже зарегистрирован"
            )

        try:
            account = Account(
                id=await Account.next_id(),
                name=user_data.name,
                email=user_data.email,
                password_hash=self._hash_password(user_data.password)
            )
            session = session_factory.get_async_or_none()
            if session is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Ошибка сервера"
                )
            session.add(account)
            log.info(f"User registered and activated successfully: {account.id}")
            return account
        except Exception as e:
            log.error(f"Ошибка регистрации: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Внутренняя ошибка сервера"
            )

    @with_async_db_session
    async def authenticate_user(self, login: LoginData) -> Optional[LoginResponse]:
        """Аутентифицирует пользователя по email и паролю.

        Args:
            login: Данные для входа (email и пароль)

        Returns:
            Optional[LoginResponse]: Данные ответа при успешной аутентификации, иначе None
        """
        account = await self._get_account_by_email(login.email)
        if not account:
            raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, message = "Пользователя не существует")
        if not self._verify_password(login.password, account.password_hash):
            raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, message = "Неверный пароль или логин")
        token = self.create_access_token({"sub": account.email})
        return LoginResponse(
            message="Успешная авторизация",
            token=token,
            account_id=account.id
        )

    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Создает JWT токен доступа.

        Args:
            data: Данные для включения в токен (обычно user_id)
            expires_delta: Время жизни токена

        Returns:
            str: JWT токен
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now() + expires_delta
        else:
            expire = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    @with_async_db_session
    async def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """Обновляет access token с помощью refresh token.

        Args:
            refresh_token: Refresh токен

        Returns:
            Optional[str]: Новый access token или None, если refresh токен невалиден
        """
        token_data = self.verify_token(refresh_token)
        if not token_data:
            return None
        account = await self._get_account_by_email(token_data.email)
        if not account:
            return None
        return self.create_access_token({"sub": account.email})

    @with_async_db_session
    async def _get_account_by_email(self, email: str) -> Optional[Account]:
        """Ищет аккаунт пользователя по email.

        Args:
            email: Email адрес для поиска

        Returns:
            Optional[Account]: Найденный аккаунт или None
        """
        session = session_factory.get_async_or_none()
        if session is None:
            raise RuntimeError("No active session available")
        result = await session.execute(
            select(Account).where(Account.email == email)
        )
        account = result.scalar_one_or_none()
        log.debug(f"Account lookup for email {email}: {'found' if account else 'not found'}")
        return account

    @with_async_db_session
    async def get_user_from_token(self, token: str = Depends(oauth2_scheme)) -> Account:
        """Проверяет токен и возвращает связанного пользователя из базы данных."""
        token_data = self.verify_token(token)
        if token_data is None:
            log.warning("Invalid or expired token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Используем _get_account_by_email для поиска пользователя
        user = await self._get_account_by_email(token_data.email)
        if user is None:
            log.warning(f"User not found for email: {token_data.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"}
            )
        if not user.is_active:
            log.warning(f"Inactive account: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is inactive"
            )

        return user


    def require_api_auth(self, required_role: Optional[str] = None) -> Callable:
        """Декоратор для защиты API эндпоинтов."""
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(func)
            async def wrapper(*args, current_user: Account = Depends(self.get_user_from_token), **kwargs):
                if required_role and current_user.role != required_role:
                    log.warning(f"Access denied for user {current_user.email}: required role {required_role}")
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Required role: {required_role}"
                    )
                log.info(f"User authenticated: {current_user.email}, role: {current_user.role}")
                return await func(*args, current_user=current_user, **kwargs)
            return wrapper
        return decorator


    def create_refresh_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Создает JWT refresh токен.

        Args:
            data: Данные для включения в токен
            expires_delta: Время жизни токена

        Returns:
            str: JWT refresh токен
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now() + expires_delta
        else:
            expire = datetime.now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    def verify_token(self, token: str) -> Boolean:
        """
        Проверяет токен на валидность.
        Args:
            token (str): JWT токен
        Returns:
            Bool: True or False
        Raises:
            HTTPException: Если токен невалиден, истек или содержит некорректные данные
        """
        try:
            # Декодирование и проверка токена
            jwt.decode(
                token,
                SECRET_KEY,
                algorithms=ALGORITHM,
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iss': False,  # Не проверяем issuer
                    'verify_aud': False  # Не проверяем audience
                }
            )
            return True

        except JWTError as e:
            print(f"Ошибка валидации токена: {str(e)}")
            return False

    def _hash_password(self, password: str) -> str:
        """Хеширует пароль.
        Args:
            password: Пароль в чистом виде
        Returns:
            str: Хеш пароля
        """
        return pwd_context.hash(password)

    def _verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Проверяет соответствие пароля и хеша.
        Args:
            plain_password: Пароль в чистом виде
            hashed_password: Хеш пароля
        Returns:
            bool: True если пароль верный, False в противном случае
        """
        return pwd_context.verify(plain_password, hashed_password)