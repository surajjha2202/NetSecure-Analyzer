import json

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog, User


def create_audit_log(
    db: Session,
    action: str,
    status: str,
    user: User | None = None,
    request: Request | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict | None = None,
) -> AuditLog:
    username = user.username if user else None
    user_id = user.id if user else None

    ip_address = None

    if request and request.client:
        ip_address = request.client.host

    audit_log = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        status=status,
        ip_address=ip_address,
        details=json.dumps(details) if details else None,
    )

    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)

    return audit_log