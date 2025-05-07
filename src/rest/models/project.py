from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel

class S3LinkData(BaseModel):
    url: str
    status: str


class ProjectData(BaseModel):
    id: Optional[int] = None
    name: str
    created_at: Optional[datetime] = None
    s3_links: Optional[List[S3LinkData]] = None


class ProjectListData(BaseModel):
    items: List[ProjectData]
    total: int
    page: int
    size: int
