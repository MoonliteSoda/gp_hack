from sqlalchemy import Column, Integer, String, ForeignKey, select, delete
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from typing import List, Optional, Tuple

from dao.base import Base, with_async_db_session, session_factory
from rest.models.project_file import ProjectFileData, ProjectFileListData


class ProjectFile(Base):
    __tablename__ = "project_files"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String, nullable=False)
    s3_path = Column(String, nullable=False)
    s3_url = Column(String, nullable=False)

    project = relationship("Project", back_populates="files")

    def to_api(self) -> ProjectFileData:
        return ProjectFileData(
            id=self.id,
            project_id=self.project_id,
            filename=self.filename,
            s3_path=self.s3_path,
            s3_url=self.s3_url
        )

    @staticmethod
    @with_async_db_session
    async def create_file(project_id: int, filename: str, s3_path: str, s3_url: str) -> "ProjectFile":
        session = session_factory.get_async()
        project_file = ProjectFile(
            project_id=project_id,
            filename=filename,
            s3_path=s3_path,
            s3_url=s3_url
        )
        session.add(project_file)
        await session.commit()
        await session.refresh(project_file)
        return project_file

    @staticmethod
    @with_async_db_session
    async def get_file_by_id(file_id: int) -> Optional["ProjectFile"]:
        session = session_factory.get_async()
        query = select(ProjectFile).where(ProjectFile.id == file_id)
        result = await session.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    @with_async_db_session
    async def get_files_by_project_id(project_id: int, filename: Optional[str] = None, status: Optional[str] = None,
                                      page: int = 1, size: int = 20) -> Tuple[List["ProjectFile"], int]:
        session = session_factory.get_async()
        query = select(ProjectFile).where(ProjectFile.project_id == project_id)
        # Здесь должен быть фильтр по статусу

        # Фильтр по имени
        if filename:
            query = query.where(ProjectFile.filename.ilike(f"%{filename}%"))

        # Получаем общее количество (с учетом фильтров)
        count_query = select(func.count()).select_from(query.subquery())
        total = await session.scalar(count_query)
        # Применяем пагинацию
        offset = (page - 1) * size
        paginated_query = query.order_by(ProjectFile.id).offset(offset).limit(size)
        # Выполняем запрос
        result = await session.execute(paginated_query)
        projects = result.scalars().all()

        return projects, total

    @staticmethod
    @with_async_db_session
    async def delete_file_by_id(file_id: int) -> None:
        session = session_factory.get_async()
        delete_query = delete(ProjectFile).where(ProjectFile.id == file_id)
        await session.execute(delete_query)
        await session.commit()
