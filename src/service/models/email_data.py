from dataclasses import dataclass

from pydantic import EmailStr
from typing import List, Optional

from templates.email_template import EmailTemplates


@dataclass
class EmailData:
    recipients: List[EmailStr]
    subject: str
    message: str
    template: Optional[EmailTemplates]
    cc: Optional[List[EmailStr]] = None
    bcc: Optional[List[EmailStr]] = None
