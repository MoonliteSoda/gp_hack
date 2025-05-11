from fastapi import APIRouter, Depends, UploadFile, File, Path, Query
from typing import List, Optional

from rest.models.project_file import ProjectFileData, ProjectFileListData
from service.file_service import FileService
from utils.logger import get_logger

log = get_logger("FileEndpoint")

router = APIRouter(prefix="/projects/{project_id}/files", tags=["files"])

@router.post("", response_model=ProjectFileData)
async def upload_file(
    project_id: int = Path(..., description="Project ID"),
    file: UploadFile = File(...),
    service: FileService = Depends()
):
    log.info(f"Received request to upload file {file.filename} to project {project_id}")
    result = await service.upload_file(project_id, file)
    log.info(f"File uploaded successfully with ID {result.id}")
    return result

@router.get("", response_model=ProjectFileListData)
async def get_project_files(
    project_id: int = Path(..., description="Project ID"),
    filename: Optional[str] = Query(None, description="Фильтр по имени файла"),
    status: Optional[str] = Query(None, description="Фильтр по статусу файла", enum=["open", "close"]),
    page: int = Query(1, ge=1, description="Номер страницы"),
    size: int = Query(20, ge=1, le=100, description="Количество элементов на странице"),
    service: FileService = Depends()
) -> ProjectFileListData:
    """
        Получить список файлов с возможностью фильтрации по имени и статусе
    """
    log.info(f"Getting files for project {project_id}, filters: filename={filename}, status={status}, page={page}, size={size}")
    result = await service.get_project_files(
        project_id=project_id,
        filename=filename,
        status=status,
        page=page,
        size=size
    )
    log.info(f"Retrieved {len(result.items)} files for project {project_id}")
    return result

@router.get("/{file_id}", response_model=ProjectFileData)
async def get_file(
    project_id: int = Path(..., description="Project ID"),
    file_id: int = Path(..., description="File ID"),
    service: FileService = Depends()
):
    log.info(f"Received request to get file {file_id} from project {project_id}")
    result = await service.get_file(file_id)
    log.info(f"Retrieved file {file_id}")
    return result

@router.delete("/{file_id}")
async def delete_file(
    project_id: int = Path(..., description="Project ID"),
    file_id: int = Path(..., description="File ID"),
    service: FileService = Depends()
):
    log.info(f"Received request to delete file {file_id} from project {project_id}")
    await service.delete_file(file_id)
    log.info(f"File {file_id} deleted successfully")
    return {"message": "File deleted successfully"}
