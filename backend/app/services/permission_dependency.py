from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from app.db.database import SessionLocal
from app.models import Role, User
from app.services.auth_dependency import get_current_user


def require_permission(permission_name: str):
    def permission_checker(
        current_user: User = Depends(get_current_user),
    ):
        db = SessionLocal()

        try:
            user = db.scalar(
                select(User)
                .options(
                    joinedload(User.role).joinedload(
                        Role.permissions
                    )
                )
                .where(User.id == current_user.id)
            )

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                )

            user_permissions = {
                permission.name
                for permission in user.role.permissions
            }

            if permission_name not in user_permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"Permission required: "
                        f"{permission_name}"
                    ),
                )

            return user

        finally:
            db.close()

    return permission_checker