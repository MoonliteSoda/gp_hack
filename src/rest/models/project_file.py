from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from enum import Enum


class YoloAnnotationData(BaseModel):
    content: str
    file_id: int


class ProjectFileStatusType(str, Enum):
    processing = "processing"
    success = "success"
    error = "error"


class ProjectFileData(BaseModel):
    id: int
    project_id: int
    filename: str
    s3_path: str
    s3_url: str
    s3_icon_path: str
    s3_icon_url: str
    s3_txt_path: str
    s3_txt_url: str
    status: ProjectFileStatusType


class ProjectFileListData(BaseModel):
    items: List[ProjectFileData]
    total: int
    page: int
    size: int
