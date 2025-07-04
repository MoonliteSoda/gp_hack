import json
import os

from utils.logger import get_logger
from fastapi import APIRouter
from rest.models.health_data import HealthData
from rest.models.version_data import VersionData

__VERSION_FILE__ = "version-info.json"
log = get_logger("SystemEndpoint")
router = APIRouter()
version_info = VersionData()

if os.path.isfile(__VERSION_FILE__):
    try:
        with open(__VERSION_FILE__) as f:
            version_info = VersionData(**json.loads(f.read()))
        log.info(f"Loaded version info: {version_info}")
    except Exception as e:
        log.error(f"Failed to load version info: {e}")


@router.get(
    "/api/health",
    responses={
        200: {"model": HealthData, "description": "Successful response"},
    },
    tags=["System"],
    response_model_by_alias=True,
)
async def health() -> HealthData:
    response = HealthData(status="Ok")
    return response

@router.get(
    "/api/version",
    responses={
        200: {"model": VersionData, "description": "Successful response"},
    },
    tags=["System"],
    response_model_by_alias=True,
)
async def version() -> VersionData:
    return version_info
