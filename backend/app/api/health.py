import redis
from app.services.permission_dependency import require_permission

from fastapi import APIRouter,Depends
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.db.database import SessionLocal
from app.services.redis_service import get_redis


router = APIRouter(tags=["System"])


@router.get("/health")
def health():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


@router.get("/health/database")
def database_health():
    db = SessionLocal()

    try:
        result = db.execute(text("SELECT 1"))
        value = result.scalar()

        return {
            "status": "healthy",
            "database": "postgresql",
            "connection": True,
            "test_query": value,
        }

    except SQLAlchemyError as exc:
        return {
            "status": "unhealthy",
            "database": "postgresql",
            "connection": False,
            "error": str(exc),
        }

    finally:
        db.close()


@router.get("/health/redis")
def redis_health():
    redis_client = get_redis()

    try:
        connected = redis_client.ping()

        return {
            "status": "healthy" if connected else "unhealthy",
            "redis": "redis",
            "connection": connected,
        }

    except redis.RedisError as exc:
        return {
            "status": "unhealthy",
            "redis": "redis",
            "connection": False,
            "error": str(exc),
        }

@router.get("/health/users")
def users_health():
    db = SessionLocal()

    try:
        count = db.execute(
            text("SELECT COUNT(*) FROM users")
        ).scalar()

        return {
            "status": "healthy",
            "table": "users",
            "count": count,
        }

    except SQLAlchemyError as exc:
        return {
            "status": "unhealthy",
            "table": "users",
            "error": str(exc),
        }

    finally:
        db.close()

@router.get("/health/protected")
def protected_health(
    current_user=Depends(
        require_permission("dashboard.view")
    ),
):
    return {
        "status": "authorized",
        "message": "You have dashboard.view permission.",
        "user": current_user.username,
        "role": current_user.role.name,
    }
