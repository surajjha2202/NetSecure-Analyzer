from fastapi import APIRouter
from app.core.config import settings

router = APIRouter(tags=["System"])


@router.get("/health")
def health():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }