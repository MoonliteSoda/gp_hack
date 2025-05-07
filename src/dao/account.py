# import enum
#
# from sqlalchemy import String, Integer, DateTime, ForeignKey, Enum, func
# from sqlalchemy.orm import Mapped, mapped_column, relationship
#
# from dao.base import Base, next_id_from_sequence
#
#
# class AccountStatus(enum.Enum):
#     active = "active"
#     deactivated = "deactivated"
#     unconfirmed = "unconfirmed"
#
# class Account(Base):
#     __tablename__ = "accounts"
#
#     id: Mapped[int] = mapped_column(Integer, primary_key=True)
#     name: Mapped[str] = mapped_column(String, nullable=False)
#     email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
#     password_hash: Mapped[str] = mapped_column(String, nullable=False)
#     status: Mapped[AccountStatus] = mapped_column(
#         Enum(AccountStatus, name="account_status"),
#         default=AccountStatus.unconfirmed,
#         nullable=False
#     )
#     created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
#
#     activation_links: Mapped[list["ActivationLink"]] = relationship("ActivationLink", back_populates="account")
#
#     @staticmethod
#     def next_id() -> int:
#         return next_id_from_sequence("account_id_seq")