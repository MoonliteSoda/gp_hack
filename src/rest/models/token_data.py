from pydantic import BaseModel
from typing import Optional


class TokenData(BaseModel):
    email: str
    access_token: Optional[str] = None
