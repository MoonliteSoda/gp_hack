from fastapi import UploadFile, HTTPException
import os
import uuid
from typing import List, Optional

from dao.base import with_async_db_session
from dao.project_file import ProjectFile
from dao.project import Project
from rest.models.project_file import ProjectFileData, ProjectFileListData
from service.s3 import S3
from utils.logger import get_logger
from utils.config import CONFIG

import tempfile

log = get_logger("FileService")


class FileService:
    def __init__(self):
        self.s3 = S3(CONFIG.s3)

    @with_async_db_session
    async def upload_file(self, project_id: int, file: UploadFile) -> ProjectFileData:
        log.info(f"Uploading file {file.filename} for project {project_id}")

        project = await Project.get_project_by_id(project_id)
        if not project:
            log.error(f"Project {project_id} not found")
            raise HTTPException(status_code=404, detail="Project not found")

        file_extension = os.path.splitext(file.filename)[1] if file.filename else ""
        unique_filename = f"{uuid.uuid4()}{file_extension}"


        s3_path = f"{project_id}/{unique_filename}"

        temp_dir = tempfile.gettempdir()
        temp_file_path = os.path.join(temp_dir, unique_filename)

        with open(temp_file_path, "wb") as temp_file:
            content = await file.read()
            temp_file.write(content)

        try:
            s3_url = self.s3.upload_file(temp_file_path, s3_path)

            project_file = await ProjectFile.create_file(
                project_id=project_id,
                filename=file.filename,
                s3_path=s3_path,
                s3_url=s3_url
            )
            os.remove(temp_file_path)

            log.info(f"File uploaded successfully: {s3_url}")
            return project_file.to_api()

        except Exception as e:
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
            log.error(f"Error uploading file: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Error uploading file: {str(e)}")

    async def delete_file(self, file_id: int) -> None:
        log.info(f"Deleting file with ID {file_id}")

        file_record = await ProjectFile.get_file_by_id(file_id)
        if not file_record:
            log.error(f"File with ID {file_id} not found")
            raise HTTPException(status_code=404, detail="File not found")

        try:
            self.s3.delete(file_record.s3_path)

            await ProjectFile.delete_file_by_id(file_id)

            log.info(f"File {file_id} deleted successfully")
        except Exception as e:
            log.error(f"Error deleting file: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Error deleting file: {str(e)}")

    async def get_file(self, file_id: int) -> ProjectFileData:
        log.info(f"Getting file with ID {file_id}")

        file_record = await ProjectFile.get_file_by_id(file_id)
        if not file_record:
            log.error(f"File with ID {file_id} not found")
            raise HTTPException(status_code=404, detail="File not found")

        return file_record.to_api()

    async def get_project_files(self, project_id: int, filename: Optional[str] = None,
                                status: Optional[str] = None, page: int = 1, size: int = 20, to_delete: bool = False) -> ProjectFileListData | list:
        log.info(f"Getting files for project {project_id}")

        project = await Project.get_project_by_id(project_id)
        if not project:
            log.error(f"Project {project_id} not found")
            raise HTTPException(status_code=404, detail="Project not found")

        files, total = await ProjectFile.get_files_by_project_id(project_id=project_id, filename=filename,
                                                                 status=status, page=page, size=size)

        if to_delete:
            file_list = [file for file in files]
            return file_list

        file_list = [file.to_api() for file in files]

        return ProjectFileListData(
            items=file_list,
            total=total,
            page=page,
            size=size
        )

