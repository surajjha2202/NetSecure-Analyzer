import hashlib
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from app.core.config import settings
from app.db.database import SessionLocal
from app.models import PasswordResetToken, Role, User
from app.schemas.auth import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserResponse,
)
from app.services.audit_service import create_audit_log
from app.services.auth_dependency import get_current_user
from app.services.email_service import send_password_reset_email
from app.services.jwt_service import create_access_token
from app.services.security import hash_password, verify_password


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    request: RegisterRequest,
    http_request: Request,
):
    db = SessionLocal()

    try:
        username = request.username.strip()
        email = request.email.strip().lower()

        if not username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username cannot be empty.",
            )

        existing_username = db.scalar(
            select(User).where(
                User.username == username
            )
        )

        if existing_username:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username is already registered.",
            )

        existing_email = db.scalar(
            select(User).where(
                User.email == email
            )
        )

        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email is already registered.",
            )

        security_analyst_role = db.scalar(
            select(Role).where(
                Role.name == "SECURITY_ANALYST"
            )
        )

        if not security_analyst_role:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    "Registration is temporarily unavailable "
                    "because the SECURITY_ANALYST role is not configured."
                ),
            )

        user = User(
            username=username,
            email=email,
            password_hash=hash_password(request.password),
            role_id=security_analyst_role.id,
            is_active=True,
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        create_audit_log(
            db=db,
            action="USER_REGISTERED",
            status="SUCCESS",
            user=user,
            request=http_request,
            resource_type="user",
            resource_id=str(user.id),
            details={
                "username": user.username,
                "email": user.email,
                "role": security_analyst_role.name,
            },
        )

        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            role=security_analyst_role.name,
            is_active=user.is_active,
        )

    except HTTPException:
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
)
def forgot_password(
    request: ForgotPasswordRequest,
    http_request: Request,
):
    db = SessionLocal()

    generic_message = (
        "If an account with that email exists, "
        "a password reset link has been sent."
    )

    try:
        email = request.email.strip().lower()

        user = db.scalar(
            select(User).where(
                User.email == email
            )
        )

        if not user:
            create_audit_log(
                db=db,
                action="PASSWORD_RESET_REQUESTED",
                status="SUCCESS",
                request=http_request,
                details={
                    "result": "no_matching_account",
                },
            )

            db.commit()

            return ForgotPasswordResponse(
                message=generic_message
            )

        now = datetime.utcnow()

        existing_tokens = db.scalars(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used_at.is_(None),
            )
        ).all()

        for existing_token in existing_tokens:
            existing_token.used_at = now

        raw_token = secrets.token_urlsafe(32)

        token_hash = hashlib.sha256(
            raw_token.encode("utf-8")
        ).hexdigest()

        expires_at = now + timedelta(
            minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES
        )

        reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
        )

        db.add(reset_token)

        reset_url = (
            f"{settings.FRONTEND_BASE_URL.rstrip('/')}"
            f"/reset-password?token={raw_token}"
        )

        try:
            send_password_reset_email(
                recipient_email=user.email,
                reset_url=reset_url,
            )

        except Exception as email_error:
            db.rollback()

            create_audit_log(
                db=db,
                action="PASSWORD_RESET_EMAIL_FAILED",
                status="FAILED",
                user=user,
                request=http_request,
                resource_type="user",
                resource_id=str(user.id),
                details={
                    "reason": type(email_error).__name__,
                },
            )

            db.commit()

            return ForgotPasswordResponse(
                message=generic_message
            )

        create_audit_log(
            db=db,
            action="PASSWORD_RESET_REQUESTED",
            status="SUCCESS",
            user=user,
            request=http_request,
            resource_type="user",
            resource_id=str(user.id),
            details={
                "expires_in_minutes": (
                    settings.PASSWORD_RESET_EXPIRE_MINUTES
                ),
            },
        )

        db.commit()

        return ForgotPasswordResponse(
            message=generic_message
        )

    except HTTPException:
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


@router.post(
    "/reset-password",
)
def reset_password(
    request: ResetPasswordRequest,
    http_request: Request,
):
    db = SessionLocal()

    try:
        token_hash = hashlib.sha256(
            request.token.encode("utf-8")
        ).hexdigest()

        reset_token = db.scalar(
            select(PasswordResetToken).where(
                PasswordResetToken.token_hash == token_hash
            )
        )

        now = datetime.utcnow()

        if (
            not reset_token
            or reset_token.used_at is not None
            or reset_token.expires_at <= now
        ):
            create_audit_log(
                db=db,
                action="PASSWORD_RESET_FAILED",
                status="FAILED",
                request=http_request,
                details={
                    "reason": "invalid_or_expired_token",
                },
            )

            db.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired password reset link.",
            )

        user = db.scalar(
            select(User).where(
                User.id == reset_token.user_id
            )
        )

        if not user:
            reset_token.used_at = now

            create_audit_log(
                db=db,
                action="PASSWORD_RESET_FAILED",
                status="FAILED",
                request=http_request,
                details={
                    "reason": "user_not_found",
                },
            )

            db.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired password reset link.",
            )

        if not user.is_active:
            reset_token.used_at = now

            create_audit_log(
                db=db,
                action="PASSWORD_RESET_FAILED",
                status="FAILED",
                user=user,
                request=http_request,
                resource_type="user",
                resource_id=str(user.id),
                details={
                    "reason": "inactive_user",
                },
            )

            db.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired password reset link.",
            )

        user.password_hash = hash_password(
            request.new_password
        )

        reset_token.used_at = now

        other_tokens = db.scalars(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.id != reset_token.id,
            )
        ).all()

        for other_token in other_tokens:
            other_token.used_at = now

        create_audit_log(
            db=db,
            action="PASSWORD_RESET_SUCCESS",
            status="SUCCESS",
            user=user,
            request=http_request,
            resource_type="user",
            resource_id=str(user.id),
        )

        db.commit()

        return {
            "message": (
                "Password reset successfully. "
                "You can now log in with your new password."
            )
        }

    except HTTPException:
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


@router.post("/login", response_model=TokenResponse)
def login(
    request: LoginRequest,
    http_request: Request,
):
    db = SessionLocal()

    try:
        user = db.scalar(
            select(User).where(
                User.username == request.username
            )
        )

        if not user:
            create_audit_log(
                db=db,
                action="LOGIN_FAILED",
                status="FAILED",
                request=http_request,
                details={"reason": "user_not_found"},
            )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )

        if not verify_password(
            request.password,
            user.password_hash,
        ):
            create_audit_log(
                db=db,
                action="LOGIN_FAILED",
                status="FAILED",
                user=user,
                request=http_request,
                details={"reason": "invalid_password"},
            )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )

        if not user.is_active:
            create_audit_log(
                db=db,
                action="LOGIN_BLOCKED",
                status="BLOCKED",
                user=user,
                request=http_request,
                details={"reason": "inactive_user"},
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive",
            )

        token = create_access_token(
            user_id=user.id,
            role=user.role.name,
        )

        create_audit_log(
            db=db,
            action="LOGIN_SUCCESS",
            status="SUCCESS",
            user=user,
            request=http_request,
        )

        return TokenResponse(
            access_token=token,
            token_type="bearer",
        )

    finally:
        db.close()


@router.get("/me", response_model=UserResponse)
def get_me(
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
                detail="User not found.",
            )

        permissions = sorted(
            permission.name
            for permission in user.role.permissions
        )

        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role.name,
            permissions=permissions,
            is_active=user.is_active,
        )

    finally:
        db.close()
