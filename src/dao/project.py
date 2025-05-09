from datetime import datetime
from typing import List, Optional, Tuple
from sqlalchemy import Column, Integer, String, DateTime, Enum, func, select, delete, update
from sqlalchemy.sql import func

from dao.base import Base, with_async_db_session, session_factory
from rest.models.project import ProjectData, ProjectStatusType

class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    status = Column(Enum(ProjectStatusType, name="project_status_type"), nullable=False, default=ProjectStatusType.open)

    def to_api(self) -> ProjectData:
        return ProjectData(
            id=self.id,
            name=self.name,
            created_at=self.created_at,
            status=self.status
        )

    @staticmethod
    @with_async_db_session
    async def create_project(name: str, status: ProjectStatusType) -> "Project":
        session = session_factory.get_async()
        project = Project(
            name=name,
            status=status
        )
        session.add(project)
        await session.commit()
        await session.refresh(project)
        return project

    @staticmethod
    @with_async_db_session
    async def get_all_projects(page: int, size: int) -> Tuple[List["Project"], int]:
        session = session_factory.get_async()
        
        # Get total count
        count_query = select(func.count()).select_from(Project)
        total = await session.scalar(count_query)
        
        # Get paginated results
        offset = (page - 1) * size
        query = select(Project).order_by(Project.id).offset(offset).limit(size)
        result = await session.execute(query)
        projects = result.scalars().all()
        
        return projects, total

    @staticmethod
    @with_async_db_session
    async def get_project_by_id(project_id: int) -> Optional["Project"]:
        session = session_factory.get_async()
        query = select(Project).where(Project.id == project_id)
        result = await session.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    @with_async_db_session
    async def delete_project_by_id(project_id: int) -> None:
        session = session_factory.get_async()
        delete_query = delete(Project).where(Project.id == project_id)
        await session.execute(delete_query)
        await session.commit()

    @staticmethod
    @with_async_db_session
    async def update_project_name(project_id: int, new_name: str) -> Optional["Project"]:
        session = session_factory.get_async()
        
        # Update project name
        update_query = update(Project).where(Project.id == project_id).values(name=new_name)
        await session.execute(update_query)
        await session.commit()
        
        # Get updated project
        query = select(Project).where(Project.id == project_id)
        result = await session.execute(query)
        return result.scalar_one_or_none()
