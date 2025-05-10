from datetime import datetime, timedelta
from typing import Optional

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy.exc import IntegrityError
from sqlalchemy.future import select

from rest.models.user_data import UserData
from rest.models.token_data import TokenData
from rest.models.login_data import LoginData
from rest.models.login_response import LoginResponse
from dao.account import Account, AccountStatus
from dao.base import session_factory
from utils.logger import get_logger


log = get_logger("AuthService")


#config_mini
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class AuthService:
    def __init__(self):
        pass


    async def register_user(self, user_data: UserData) -> Account:
        """Регистрирует нового пользователя без подтверждения email.
        Аккаунт становится активным сразу после регистрации.

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
            raise ValueError(f"User with email {user_data.email} already exists")

        try:
            async with session_factory as session:
                account = Account(
                    id= await Account.next_id(),
                    name=user_data.name,
                    email=user_data.email,
                    password_hash=self._hash_password(user_data.password)
                )

                session.add(account)
                await session.commit()

                log.info(f"User registered and activated successfully: {account.id}")
                return account

        except IntegrityError as e:
            log.error(f"Database error during registration: {e}")
            raise ValueError("Registration failed due to database constraints")
        except Exception as e:
            log.error(f"Unexpected error during registration: {e}")
            raise

    async def authenticate_user(self,login:LoginData) -> LoginResponse | None:
        """Аутентифицирует пользователя по email и паролю.

        Args:
            login: Данные для входа (email и пароль)

        Returns:
            Optional[str]: JWT-токен при успешной аутентификации, иначе None
        """
        #log.info(f"не долшли до дб")
        account = await self._get_account_by_email(login.email)
        #log.info("дошли до дб")
        if not account:
            return None
        if not self._verify_password(login.password, account.password_hash):
            return None
        #log.info("до получения токена")
        token = self.create_access_token({"sub": account.email})
        #log.info(f"после получения токена")
        result = LoginResponse(message = "Успешная авторизация",
                               token = token,
                               account_id = account.id)
        return result


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


    def verify_token(self, token: str) -> Optional[TokenData]:
        """Верифицирует JWT токен и возвращает данные из него.

        Args:
            token: JWT токен

        Returns:
            Optional[TokenData]: Данные из токена или None, если токен невалиден
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            email: str = payload.get("sub")
            if email is None:
                return None
            return TokenData(email=email)
        except JWTError:
            return None


    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """Обновляет access token с помощью refresh token.

        Args:
            refresh_token: Refresh токен

        Returns:
            Optional[str]: Новый access token или None, если refresh токен невалиден
        """
        token_data = self.verify_token(refresh_token)
        if not token_data:
            return None

        account = self._get_account_by_email(token_data.email)
        if not account:
            return None

        return self.create_access_token({"sub": account.email})


    async def _get_account_by_email(self, email: str) -> Optional[Account]:
        """Ищет аккаунт пользователя по email.

        Args:
            email: Email адрес для поиска

        Returns:
            Optional[Account]: Найденный аккаунт или None
        """
        async with session_factory as session:
            result = await session.execute(
                select(Account).where(Account.email == email)
            )
            return result.scalar_one_or_none()


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

