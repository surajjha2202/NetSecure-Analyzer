from datetime import datetime

from sqlalchemy import DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class BulkAnalysisJob(Base):
    __tablename__ = "bulk_analysis_jobs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="PENDING",
        index=True,
    )

    total_configurations: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    successful: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    failed: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    selected_frameworks: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
    )

    summary: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    results: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    created_by: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )