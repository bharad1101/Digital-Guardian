"""user_settings: add created_at and backfill updated_at default

Revision ID: 0003_user_settings_timestamps
Revises: 0002_platform_upgrade
Create Date: 2026-01-01 00:00:02

The model declares ``UserSettings.created_at`` (NOT NULL) and
``UserSettings.updated_at`` (NOT NULL), but revision 0002 created the
user_settings table without ``created_at`` and with a nullable
``updated_at``. This migration brings migrated databases in line with the
model so that SELECT/INSERT of user settings works.
"""

from alembic import op
import sqlalchemy as sa

revision = "0003_user_settings_timestamps"
down_revision = "0002_platform_upgrade"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("user_settings") as batch_op:
        batch_op.add_column(
            sa.Column(
                "created_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            )
        )
        batch_op.alter_column(
            "updated_at",
            existing_type=sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        )


def downgrade():
    with op.batch_alter_table("user_settings") as batch_op:
        batch_op.drop_column("created_at")
        batch_op.alter_column(
            "updated_at",
            existing_type=sa.DateTime(),
            nullable=True,
            server_default=None,
        )