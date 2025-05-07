from rest.models.user_data import UserData
from utils.logger import get_logger

log = get_logger("AuthService")


class AuthService:

    def __init__(self):
        pass

    # @with_async_db_session
    async def register_user(self, user_data: UserData):
        pass
        # await self.email_service.send_email(EmailData(recipients = [user_data.email], subject = "Специально для Артура", message = "Вы отправили регистрацию в лучший сервис", template = EmailTemplates.DEFAULT_MESSAGE))
        # existing_account = await self._get_account_by_email(user_data.email)
        # if existing_account:
        #     log.warning(f"User with email {user_data.email} already exists")
        #     raise ValueError(f"User with email {user_data.email} already exists")
        #
        # try:
        #     account = Account(
        #         id=Account.next_id(),
        #         name=user_data.name,
        #         email=user_data.email,
        #         password_hash=self._hash_password(user_data.password),
        #         status=AccountStatus.unconfirmed
        #     )
        #
        #     session = session_factory.get()
        #     session.add(account)
        #     await session.flush()
        #
        #     activation_token = self._generate_activation_token()
        #     expiration_date = datetime.now() + timedelta(days=1)
        #
        #     activation_link = ActivationLink(
        #         token=activation_token,
        #         account_id=account.id,
        #         expires_at=expiration_date
        #     )
        #
        #     session.add(activation_link)
        #     await session.commit()
        #
        #
        #     # await self._send_activation_email(account.email, activation_token)
        #
        #     log.info(f"User registered successfully: {account.id}")
        #
        #
        # except IntegrityError as e:
        #     log.error(f"Failed to register user: {e}")
        #     raise ValueError("Failed to register user due to database constraint")
        # except Exception as e:
        #     log.error(f"Unexpected error during user registration: {e}")
        #     raise
    
    # @with_async_db_session
    # async def _get_account_by_email(self, email: str) -> Optional[Account]:
    #     session = session_factory.open()
    #     query = select(Account).where(Account.email == email)
    #     result = await session.execute(query)
    #     return result.scalar_one_or_none()
    #
    # def _hash_password(self, password: str) -> str:
    #     return f"hashed_{password}"
    #
    # def _generate_activation_token(self, length: int = 32) -> str:
    #     """Генерирует случайный токен для активации аккаунта"""
    #     alphabet = string.ascii_letters + string.digits
    #     return ''.join(secrets.choice(alphabet) for _ in range(length))

