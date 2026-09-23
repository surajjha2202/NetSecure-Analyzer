"""add device ownership

Revision ID: add_device_owner
Revises: 5dac540be721
Create Date: 2026-09-20
"""

from alembic import op
import sqlalchemy as sa


revision = "add_device_owner"
down_revision = "5dac540be721"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "devices",
        sa.Column("owner_id", sa.Integer(), nullable=True),
    )

    op.create_index(
        "ix_devices_owner_id",
        "devices",
        ["owner_id"],
    )

    op.create_foreign_key(
        "fk_devices_owner_id_users",
        "devices",
        "users",
        ["owner_id"],
        ["id"],
    )

    # Preserve all existing devices under the existing admin account.
    op.execute(
        "UPDATE devices SET owner_id = 1 WHERE owner_id IS NULL"
    )

    op.alter_column(
        "devices",
        "owner_id",
        existing_type=sa.Integer(),
        nullable=False,
    )


def downgrade():
    op.drop_constraint(
        "fk_devices_owner_id_users",
        "devices",
        type_="foreignkey",
    )

    op.drop_index(
        "ix_devices_owner_id",
        table_name="devices",
    )

    op.drop_column("devices", "owner_id")
