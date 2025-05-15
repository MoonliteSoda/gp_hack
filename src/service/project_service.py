from typing import List, Optional

from dao.base import with_async_db_session
from dao.project import Project
from rest.models.project import ProjectData, ProjectListData, CreateProjectData, ProjectStatusType
from utils.logger import get_logger

from datetime import datetime

log = get_logger("ProjectService")

class ProjectService:

    @with_async_db_session
    async def create_project(self, project_data: CreateProjectData) -> ProjectData:
        log.info(f"Creating project: {project_data.name}")
        project = await Project.create_project(project_data.name, ProjectStatusType.open)
        return project.to_api()

    @with_async_db_session
    async def search_projects(self, name: Optional[str] = None, start_date: Optional[datetime] = None,
                              end_date: Optional[datetime] = None, page: int = 1, size: int = 20) -> ProjectListData:
        log.info(f"Getting projects, filters: name={name}, date_range={start_date}-{end_date}")

        projects, total = await Project.search_projects(name=name, start_date=start_date,
                                                        end_date=end_date, page=page, size=size)

        items = [project.to_api() for project in projects]

        return ProjectListData(
            items=items,
            total=total,
            page=page,
            size=size
        )

    @with_async_db_session
    async def get_project(self, project_id: int) -> ProjectData:
        log.info(f"Getting project with id: {project_id}")

        project = await Project.get_project_by_id(project_id)

        if not project:
            raise ValueError(f"Project with id {project_id} not found")

        return project.to_api()

    @with_async_db_session
    async def delete_project(self, project_id: int) -> None:
        log.info(f"Deleting project with id: {project_id}")

        # Check if project exists
        project = await Project.get_project_by_id(project_id)

        if not project:
            raise ValueError(f"Project with id {project_id} not found")

        # Delete project
        await Project.delete_project_by_id(project_id)

    @with_async_db_session
    async def update_project_name(self, project_id: int, new_name: str) -> ProjectData:
        log.info(f"Updating project {project_id} name to: {new_name}")

        # Check if project exists
        project = await Project.get_project_by_id(project_id)

        if not project:
            raise ValueError(f"Project with id {project_id} not found")

        # Update project name
        updated_project = await Project.update_project_name(project_id, new_name)

        if not updated_project:
            raise ValueError(f"Failed to update project with id {project_id}")

        return updated_project.to_api()

    @with_async_db_session
    async def update_project_status(self, project_id: int):
        log.info(f"Updating project {project_id} status")

        # Check if project exists
        project = await Project.get_project_by_id(project_id)

        if not project:
            raise ValueError(f"Project with id {project_id} not found")

        # Update project status
        updated_project = await Project.update_project_status(project_id)

        if not updated_project:
            raise ValueError(f"Failed to update project with id {project_id}")

        return updated_project.to_api()
