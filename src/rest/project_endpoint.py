from fastapi import APIRouter, Depends, Query
from typing import List, Optional

from service.project_service import ProjectService
from rest.models.project import ProjectData, ProjectListData

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.post("", response_model=ProjectData)
async def create_project(project_data: ProjectData, service: ProjectService = Depends())-> ProjectData:
    pass


@router.get("", response_model=ProjectListData)
async def get_all_projects(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    service: ProjectService = Depends(),
) -> ProjectListData:
    pass


@router.get("/{project_id}", response_model=ProjectData)
async def get_project(project_id: int, service: ProjectService = Depends()) -> ProjectData:
    pass


@router.delete("/{project_id}")
async def delete_project(project_id: int, service: ProjectService = Depends()):
    pass


@router.put("/{project_id}/name", response_model=ProjectData)
async def update_project_name(
    project_id: int, project_data: ProjectData, service: ProjectService = Depends()
) -> ProjectData:
    pass
