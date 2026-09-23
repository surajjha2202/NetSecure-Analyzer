from sqlalchemy import select

from app.db.database import SessionLocal
from app.models import Permission, Role


ROLE_PERMISSIONS = {
    "ADMIN": [
        "dashboard.view",
        "devices.view",
        "devices.manage",
        "scans.view",
        "scans.run",
        "configs.upload",
        "configs.view",
        "compliance.view",
        "compliance.manage",
        "reports.view",
        "reports.generate",
        "remediation.view",
        "remediation.approve",
        "remediation.execute",
        "audit.view",
    ],

    "SECURITY_ANALYST": [
        "dashboard.view",
        "devices.view",
        "devices.manage",
        "scans.view",
        "scans.run",
        "configs.upload",
        "configs.view",
        "compliance.view",
        "compliance.manage",
        "reports.view",
        "reports.generate",
        "remediation.view",
        "remediation.approve",
        "remediation.execute",
        "audit.view",
    ],

    "AUDITOR": [
        "dashboard.view",
        "devices.view",
        "devices.manage",
        "scans.view",
        "scans.run",
        "configs.upload",
        "configs.view",
        "compliance.view",
        "compliance.manage",
        "reports.view",
        "reports.generate",
        "remediation.view",
        "remediation.approve",
        "remediation.execute",
        "audit.view",
    ],

    "VIEWER": [
        "dashboard.view",
        "devices.view",
        "devices.manage",
        "scans.view",
        "scans.run",
        "configs.upload",
        "configs.view",
        "compliance.view",
        "compliance.manage",
        "reports.view",
        "reports.generate",
        "remediation.view",
        "remediation.approve",
        "remediation.execute",
        "audit.view",
    ],
}

def seed_role_permissions() -> None:
    db = SessionLocal()

    try:
        for role_name, permission_names in ROLE_PERMISSIONS.items():
            role = db.scalar(
                select(Role).where(
                    Role.name == role_name
                )
            )

            if not role:
                raise RuntimeError(
                    f"Role '{role_name}' does not exist."
                )

            desired_permissions = set(permission_names)

            # Load all permissions currently assigned to this role.
            current_permissions = {
                permission.name: permission
                for permission in role.permissions
            }

            # Remove permissions that are no longer part of the role definition.
            role.permissions = [
                permission
                for permission in role.permissions
                if permission.name in desired_permissions
            ]

            # Add permissions that are missing.
            for permission_name in desired_permissions:
                permission = db.scalar(
                    select(Permission).where(
                        Permission.name == permission_name
                    )
                )

                if not permission:
                    raise RuntimeError(
                        f"Permission '{permission_name}' does not exist."
                    )

                if permission_name not in current_permissions:
                    role.permissions.append(permission)

        db.commit()

        print("Role-permission assignments synchronized successfully.")

        for role_name, permission_names in ROLE_PERMISSIONS.items():
            print(
                f"{role_name}: {len(permission_names)} permissions"
            )

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


if __name__ == "__main__":
    seed_role_permissions()
