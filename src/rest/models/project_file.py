from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


class YoloAnnotationData(BaseModel):
    content: str
    file_id: int


class ProjectFileData(BaseModel):
    id: Optional[int] = None
    project_id: int
    filename: str
    file_path: str
    file_size: int
    mime_type: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    has_annotation: bool = False


class ProjectFileListData(BaseModel):
    items: List[ProjectFileData]
    total: int
    page: int
    size: int
