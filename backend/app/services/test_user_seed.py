from sqlalchemy import select

from app.db.database import SessionLocal
from app.models import Role, User
from app.services.security import hash_password


def create_viewer_test_user() -> None:
    db = SessionLocal()

    try:
        existing_user = db.scalar(
            select(User).where(
                User.username == "viewer_test"
            )
        )

        if existing_user:
            print("Viewer test user already exists.")
            return

        viewer_role = db.scalar(
            select(Role).where(
                Role.name == "VIEWER"
            )
        )

        if not viewer_role:
            raise RuntimeError(
                "VIEWER role does not exist."
            )

        user = User(
            username="viewer_test",
            email="viewer_test@netsecure.com",
            password_hash=hash_password(
                "ViewerTestPassword123!"
            ),
            role_id=viewer_role.id,
            is_active=True,
        )

        db.add(user)
        db.commit()

        print("Viewer test user created successfully.")

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


if __name__ == "__main__":
    create_viewer_test_user()