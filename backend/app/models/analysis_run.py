from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    configuration_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("configurations.id"),
        nullable=False,
        index=True,
    )

    analyzed_by: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="COMPLETED",
        index=True,
    )

    selected_frameworks: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
    )

    device_intelligence: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    parser: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    security_baseline: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    compliance: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    framework_results: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    ai_ingestion: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    unknown_lines: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    risk: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    remediation: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )
