from datetime import datetime

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class TrainingCandidate(Base):
    __tablename__ = "training_candidates"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    configuration_id: Mapped[int] = mapped_column(
        ForeignKey("configurations.id"),
        nullable=False,
        index=True,
    )

    configuration_line: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    suggested_category: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    suggested_baseline_parameter: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    suggested_expected_value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )

    confidence_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="LOW",
    )

    evidence: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="semantic_nlp",
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="PENDING",
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    reviewed_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    learned_mapping_id: Mapped[int | None] = mapped_column(
        ForeignKey("learned_mappings.id"),
        nullable=True,
        index=True,
    )
