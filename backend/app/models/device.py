from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    owner_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    hostname: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    management_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
        index=True,
    )

    vendor: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    product: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    platform: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    model: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    firmware: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    serial_number: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    device_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    connection_method: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    last_scan_status: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    last_scanned_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )
