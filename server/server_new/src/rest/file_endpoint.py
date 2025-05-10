from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from typing import List, Optional

from rest.models.project_file import ProjectFileData, ProjectFileListData, YoloAnnotationData
from service.file_service import FileService

router = APIRouter(prefix="/api/projects/{project_id}/files", tags=["project files"])


@router.post("", response_model=ProjectFileData)
async def upload_file(
    project_id: int, 
    file: UploadFile = File(...), 
    service: FileService = Depends()
) -> ProjectFileData:
    pass
    # """Загрузка файла в проект"""
    # return await service.upload_file(project_id, file)


@router.get("", response_model=ProjectFileListData)
async def get_project_files(
    project_id: int,
    page: int = 1,
    size: int = 20,
    service: FileService = Depends()
) -> ProjectFileListData:
    pass
    # """Получение списка файлов проекта"""
    # return await service.get_project_files(project_id, page, size)


@router.get("/{file_id}", response_model=ProjectFileData)
async def get_file(
    project_id: int,
    file_id: int,
    service: FileService = Depends()
) -> ProjectFileData:
    pass
    # """Получение информации о файле"""
    # return await service.get_file(project_id, file_id)


@router.delete("/{file_id}")
async def delete_file(
    project_id: int,
    file_id: int,
    service: FileService = Depends()
):
    pass
    # """Удаление файла из проекта"""
    # await service.delete_file(project_id, file_id)


@router.get("/{file_id}/content")
async def get_file_content(
    project_id: int,
    file_id: int,
    service: FileService = Depends()
):
    pass
    # """Получение содержимого файла"""
    # return await service.get_file_content(project_id, file_id)


@router.get("/{file_id}/annotation", response_model=YoloAnnotationData)
async def get_file_annotation(
    project_id: int,
    file_id: int,
    service: FileService = Depends()
) -> YoloAnnotationData:
    pass
    # return await service.get_file_annotation(project_id, file_id)


@router.put("/{file_id}/annotation", response_model=YoloAnnotationData)
async def update_file_annotation(
    project_id: int,
    file_id: int,
    annotation: YoloAnnotationData,
    service: FileService = Depends()
) -> YoloAnnotationData:
    pass
    # return await service.update_file_annotation(project_id, file_id, annotation)


@router.post("/{file_id}/annotation", response_model=YoloAnnotationData)
async def upload_annotation_file(
    project_id: int,
    file_id: int,
    annotation_file: UploadFile = File(...),
    service: FileService = Depends()
) -> YoloAnnotationData:
    pass
    # return await service.upload_annotation_file(project_id, file_id, annotation_file)
