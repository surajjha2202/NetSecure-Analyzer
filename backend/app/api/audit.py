import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.db.database import SessionLocal
from app.models import AuditLog, User
from app.services.auth_dependency import get_current_user


router = APIRouter(
    prefix="/audit",
    tags=["Audit"],
)


@router.get("/logs")
def get_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: str | None = Query(None),
    status: str | None = Query(None),
    username: str | None = Query(None),
    resource_type: str | None = Query(None),
    current_user: User = Depends(get_current_user),
):
    db = SessionLocal()

    try:
        query = select(AuditLog).where(
            AuditLog.user_id == current_user.id
        )

        if action:
            query = query.where(
                AuditLog.action == action
            )

        if status:
            query = query.where(
                AuditLog.status == status
            )

        if username:
            query = query.where(
                AuditLog.username == username
            )

        if resource_type:
            query = query.where(
                AuditLog.resource_type == resource_type
            )

        count_query = select(
            func.count()
        ).select_from(
            query.subquery()
        )

        total_count = db.scalar(count_query) or 0

        offset = (page - 1) * page_size

        logs = db.scalars(
            query
            .order_by(AuditLog.created_at.desc())
            .offset(offset)
            .limit(page_size)
        ).all()

        total_pages = (
            (total_count + page_size - 1) // page_size
            if total_count
            else 0
        )

        return {
            "count": len(logs),
            "total_count": total_count,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "filters": {
                "action": action,
                "status": status,
                "username": username,
                "resource_type": resource_type,
            },
            "logs": [
                {
                    "id": log.id,
                    "user_id": log.user_id,
                    "username": log.username,
                    "action": log.action,
                    "status": log.status,
                    "resource_type": log.resource_type,
                    "resource_id": log.resource_id,
                    "ip_address": log.ip_address,
                    "details": (
                        json.loads(log.details)
                        if log.details
                        else None
                    ),
                    "created_at": log.created_at,
                }
                for log in logs
            ],
        }

    finally:
        db.close()
