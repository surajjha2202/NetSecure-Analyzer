from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.health import router as health_router
from app.api.auth import router as auth_router
from app.api.audit import router as audit_router
from app.api.configurations import router as configurations_router
from app.api.devices import router as devices_router
from app.api.bulk import router as bulk_router
from app.api.remediation import router as remediation_router
from app.api.training import router as training_router


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Enterprise multi-vendor network security compliance platform",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=list(
        dict.fromkeys(
            [
                settings.FRONTEND_BASE_URL,
                "http://localhost:5173",
                "http://127.0.0.1:5173",
            ]
        )
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(
    health_router,
    prefix="/api",
)

app.include_router(
    auth_router,
    prefix="/api",
)

app.include_router(
    audit_router,
    prefix="/api",
)

app.include_router(
    configurations_router,
    prefix="/api",
)

app.include_router(
    devices_router,
    prefix="/api",
)

app.include_router(
    bulk_router,
    prefix="/api",
)

app.include_router(
    remediation_router,
    prefix="/api",
)

app.include_router(
    training_router,
    prefix="/api",
)


@app.get("/")
def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
    }