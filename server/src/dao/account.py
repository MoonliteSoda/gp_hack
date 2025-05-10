import enum
from datetime import datetime

from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy import String, Integer, DateTime, ForeignKey, Enum, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dao.base import Base, next_id_from_sequence_async


class AccountStatus(enum.Enum):
    active = "active"
    deactivated = "deactivated"
    unconfirmed = "unconfirmed"

class Account(Base):
    __tablename__ = 'accounts'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)  # Статус вместо AccountStatus
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    role = Column(String(50), default='user')  # Простая роль вместо сложной системы

    @staticmethod
    async def next_id() -> int:
        return await next_id_from_sequence_async("accounts_id_seq")

"""class Account(Base):

     __tablename__ = "accounts"

     id: Mapped[int] = mapped_column(Integer, primary_key=True)#

     name: Mapped[str] = mapped_column(String, nullable=False)
     email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
     password_hash: Mapped[str] = mapped_column(String, nullable=False)
     status: Mapped[AccountStatus] = mapped_column(
         Enum(AccountStatus, name="account_status"),
         default=AccountStatus.unconfirmed,
         nullable=False
     )
     created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

     activation_links: Mapped[list["ActivationLink"]] = relationship("ActivationLink", back_populates="account")"""
