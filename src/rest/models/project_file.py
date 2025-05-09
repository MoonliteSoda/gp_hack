from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


class YoloAnnotationData(BaseModel):
    content: str
    file_id: int


class ProjectFileData(BaseModel):
    id: int
    project_id: int
    filename: str
    s3_path: str
    s3_url: str


class ProjectFileListData(BaseModel):
    items: List[ProjectFileData]
    total: int
    page: int
    size: int
