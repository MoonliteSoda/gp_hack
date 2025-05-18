from pydantic import BaseModel, EmailStr


class UserResponseData(BaseModel):
    id: int
    email: EmailStr
    name: str