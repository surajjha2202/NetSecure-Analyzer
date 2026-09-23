import os
from dotenv import load_dotenv
from sqlalchemy import select

load_dotenv()

from app.db.database import SessionLocal
from app.models import Role, User
from app.services.security import hash_password


def create_admin_user() -> None:
    username = os.getenv("ADMIN_USERNAME")
    email = os.getenv("ADMIN_EMAIL")
    password = os.getenv("ADMIN_PASSWORD")

    if not username or not email or not password:
        raise RuntimeError(
            "ADMIN_USERNAME, ADMIN_EMAIL and ADMIN_PASSWORD "
            "environment variables are required."
        )

    db = SessionLocal()

    try:
        existing_user = db.scalar(
            select(User).where(User.username == username)
        )

        if existing_user:
            print(f"Admin user '{username}' already exists.")
            return

        admin_role = db.scalar(
            select(Role).where(Role.name == "ADMIN")
        )

        if not admin_role:
            raise RuntimeError("ADMIN role does not exist.")

        admin_user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            role_id=admin_role.id,
            is_active=True,
        )

        db.add(admin_user)
        db.commit()

        print(f"Admin user '{username}' created successfully.")

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()