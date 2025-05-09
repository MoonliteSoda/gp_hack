import secrets
import string

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from sqlalchemy.exc import IntegrityError

from rest.models.user_data import UserData
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

    # @with_async_db_session
    async def register_user(self, user_data: UserData):
        """Регистрирует нового пользователя без подтверждения email.

        Пользователь становится активным сразу после регистрации.
        Args:
            user_data: Объект с данными пользователя (email, password, name)

        Returns:
            Account: Созданный аккаунт пользователя

        Raises:
            ValueError: Если пользователь с таким email уже существует
            IntegrityError: При нарушении ограничений базы данных
            Exception: При других непредвиденных ошибках

        Example:
            user_data = UserData(email="test@example.com", password="qwerty", name="Test")
            auth = AuthService()
            account = await auth.register_user(user_data)
        """
        existing_account = await self._get_account_by_email(user_data.email)
        if existing_account:
             log.warning(f"User with email {user_data.email} already exists")
             raise ValueError(f"User with email {user_data.email} already exists")

        try:
             account = Account(
                 id=Account.next_id(),
                 name=user_data.name,
                 email=user_data.email,
                 password_hash=self._hash_password(user_data.password),
                 status=AccountStatus.active
             )

             session = session_factory.get()
             session.add(account)
             await session.flush()

             activation_token = self._generate_activation_token()
             expiration_date = datetime.now() + timedelta(days=1)

             activation_link = ActivationLink(
                 token=activation_token,
                 account_id=account.id,
                 expires_at=expiration_date
             )

             session.add(activation_link)
             await session.commit()


             await self._send_activation_email(account.email, activation_token)

            log.info(f"User registered successfully: {account.id}")


        except IntegrityError as e:
            log.error(f"Failed to register user: {e}")
            raise ValueError("Failed to register user due to database constraint")
        except Exception as e:
            log.error(f"Unexpected error during user registration: {e}")
            raise

        #@with_async_db_session
        async def _get_account_by_email(self, email: str) -> Optional[Account]:
            """Ищет аккаунт пользователя по email.
            Args:
                email: Email адрес для поиска
            Returns:
                Optional[Account]: Найденный аккаунт или None, если не найден
            Note:
                Использует асинхронную сессию БД через декоратор @with_async_db_session
            """
            session = session_factory.open()
            query = select(Account).where(Account.email == email)
            result = await session.execute(query)
            return result.scalar_one_or_none()

        def _hash_password(self, password: str) -> str:
            """
            Функция для хеширование пароля
            :param password: строка пароль передается в функцию
            :return: возвращает строку которая является хэшированной стрококой
            """
            return pwd_context.hash(password)

        def _generate_activation_token(self, length: int = 32) -> str:
            """Генерирует случайный токен для активации аккаунта"""
            alphabet = string.ascii_letters + string.digits
            return ''.join(secrets.choice(alphabet) for _ in range(length))

