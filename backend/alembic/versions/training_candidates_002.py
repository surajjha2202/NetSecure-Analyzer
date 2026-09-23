"""add configuration provenance to training candidates

Revision ID: training_candidates_002
Revises: training_candidates_001
Create Date: 2026-09-16
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "training_candidates_002"
down_revision: Union[str, Sequence[str], None] = "training_candidates_001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add configuration provenance to training candidates."""

    op.add_column(
        "training_candidates",
        sa.Column(
            "configuration_id",
            sa.Integer(),
            nullable=True,
        ),
    )

    op.create_foreign_key(
        "fk_training_candidates_configuration_id",
        "training_candidates",
        "configurations",
        ["configuration_id"],
        ["id"],
    )

    op.create_index(
        op.f("ix_training_candidates_configuration_id"),
        "training_candidates",
        ["configuration_id"],
        unique=False,
    )


def downgrade() -> None:
    """Remove configuration provenance."""

    op.drop_index(
        op.f("ix_training_candidates_configuration_id"),
        table_name="training_candidates",
    )

    op.drop_constraint(
        "fk_training_candidates_configuration_id",
        "training_candidates",
        type_="foreignkey",
    )

    op.drop_column(
        "training_candidates",
        "configuration_id",
    )
