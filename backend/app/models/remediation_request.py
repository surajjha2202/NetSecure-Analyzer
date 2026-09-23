from datetime import datetime

from sqlalchemy import DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class RemediationRequest(Base):
    __tablename__ = "remediation_requests"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    configuration_id: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        index=True,
    )

    device_id: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        index=True,
    )

    rule_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    control: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    vendor: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    command: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    parameters: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    explanation: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    state: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="PENDING",
        index=True,
    )

    requested_by: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True,
    )

    requested_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    approved_by: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    rejected_by: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    rejected_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    executed_by: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    executed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    execution_status: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    execution_output: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    verification_result: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )