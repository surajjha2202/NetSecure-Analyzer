from fastapi import FastAPI

from app.core.config import settings
from app.api.health import router as health_router


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Enterprise multi-vendor network security compliance platform",
)


app.include_router(
    health_router,
    prefix="/api",
)


@app.get("/")
def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
    }