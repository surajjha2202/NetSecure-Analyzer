"""add remediation request parameters

Revision ID: 2ba577f559c0
Revises: training_candidates_002
Create Date: ...
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "2ba577f559c0"
down_revision: Union[str, Sequence[str], None] = "training_candidates_002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "remediation_requests",
        sa.Column(
            "parameters",
            sa.JSON(),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column(
        "remediation_requests",
        "parameters",
    )