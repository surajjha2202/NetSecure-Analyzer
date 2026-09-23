"""create training candidates table

Revision ID: training_candidates_001
Revises: e658b61634a3
Create Date: 2026-09-16
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "training_candidates_001"
down_revision: Union[str, Sequence[str], None] = "e658b61634a3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create training candidates table."""
    op.create_table(
        "training_candidates",
        sa.Column(
            "id",
            sa.Integer(),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column(
            "configuration_line",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "suggested_category",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column(
            "suggested_baseline_parameter",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "suggested_expected_value",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "confidence",
            sa.Float(),
            nullable=False,
        ),
        sa.Column(
            "confidence_level",
            sa.String(length=20),
            nullable=False,
        ),
        sa.Column(
            "evidence",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "source",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
        ),
        sa.Column(
            "reviewed_at",
            sa.DateTime(),
            nullable=True,
        ),
        sa.Column(
            "reviewed_by",
            sa.Integer(),
            nullable=True,
        ),
        sa.Column(
            "learned_mapping_id",
            sa.Integer(),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["reviewed_by"],
            ["users.id"],
        ),
        sa.ForeignKeyConstraint(
            ["learned_mapping_id"],
            ["learned_mappings.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        op.f("ix_training_candidates_id"),
        "training_candidates",
        ["id"],
        unique=False,
    )

    op.create_index(
        op.f("ix_training_candidates_status"),
        "training_candidates",
        ["status"],
        unique=False,
    )

    op.create_index(
        op.f("ix_training_candidates_reviewed_by"),
        "training_candidates",
        ["reviewed_by"],
        unique=False,
    )

    op.create_index(
        op.f("ix_training_candidates_learned_mapping_id"),
        "training_candidates",
        ["learned_mapping_id"],
        unique=False,
    )


def downgrade() -> None:
    """Drop training candidates table."""
    op.drop_index(
        op.f("ix_training_candidates_learned_mapping_id"),
        table_name="training_candidates",
    )
    op.drop_index(
        op.f("ix_training_candidates_reviewed_by"),
        table_name="training_candidates",
    )
    op.drop_index(
        op.f("ix_training_candidates_status"),
        table_name="training_candidates",
    )
    op.drop_index(
        op.f("ix_training_candidates_id"),
        table_name="training_candidates",
    )
    op.drop_table("training_candidates")
