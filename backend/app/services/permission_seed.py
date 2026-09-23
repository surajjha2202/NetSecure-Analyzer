from sqlalchemy import select

from app.db.database import SessionLocal
from app.models import Permission


PERMISSIONS = [
    (
        "dashboard.view",
        "View the NetSecure Analyzer dashboard",
    ),
    (
        "users.view",
        "View users",
    ),
    (
        "users.manage",
        "Create, update and deactivate users",
    ),
    (
        "roles.view",
        "View roles and permissions",
    ),
    (
        "roles.manage",
        "Manage roles and permissions",
    ),
    (
        "devices.view",
        "View network devices",
    ),
    (
        "devices.manage",
        "Add, update and remove network devices",
    ),
    (
        "scans.view",
        "View security scans",
    ),
    (
        "scans.run",
        "Run security scans",
    ),
    (
        "configs.upload",
        "Upload network configuration files",
    ),
    (
        "configs.view",
        "View uploaded configurations",
    ),
    (
        "compliance.view",
        "View compliance results",
    ),
    (
        "compliance.manage",
        "Manage compliance configuration",
    ),
    (
        "reports.view",
        "View security reports",
    ),
    (
        "reports.generate",
        "Generate security reports",
    ),
    (
        "remediation.view",
        "View remediation recommendations",
    ),
    (
        "remediation.approve",
        "Approve remediation actions",
    ),
    (
    "remediation.execute",
    "Execute approved remediation actions on network devices",
    ),
    (
        "audit.view",
        "View audit logs",
    ),
]


def seed_permissions() -> None:
    db = SessionLocal()

    try:
        created = 0
        existing = 0

        for name, description in PERMISSIONS:
            permission = db.scalar(
                select(Permission).where(
                    Permission.name == name
                )
            )

            if permission:
                existing += 1
                continue

            db.add(
                Permission(
                    name=name,
                    description=description,
                )
            )

            created += 1

        db.commit()

        print(f"Permissions created: {created}")
        print(f"Permissions already existing: {existing}")

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


if __name__ == "__main__":
    seed_permissions()