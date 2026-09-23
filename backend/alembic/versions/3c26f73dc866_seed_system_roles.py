"""Seed system roles

Revision ID: 3c26f73dc866
Revises: 37e51432b5d9
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "3c26f73dc866"
down_revision: Union[str, Sequence[str], None] = "37e51432b5d9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    roles_table = sa.table(
        "roles",
        sa.column("name", sa.String),
        sa.column("description", sa.String),
    )

    op.bulk_insert(
        roles_table,
        [
            {
                "name": "ADMIN",
                "description": "Full platform administration",
            },
            {
                "name": "SECURITY_ANALYST",
                "description": "Run scans and analyze security compliance",
            },
            {
                "name": "AUDITOR",
                "description": "Review compliance, findings, history and reports",
            },
            {
                "name": "VIEWER",
                "description": "Read-only platform access",
            },
        ],
    )


def downgrade() -> None:
    op.execute(
        """
        DELETE FROM roles
        WHERE name IN (
            'ADMIN',
            'SECURITY_ANALYST',
            'AUDITOR',
            'VIEWER'
        )
        """
    )