"""baseline legacy schema

Revision ID: 0001_baseline
Revises:
Create Date: 2026-01-01 00:00:00

Represents the original Digital Guardian schema (User + Scan) exactly as
it existed before the platform upgrade. Existing databases are stamped to
this revision; fresh databases run it first and are then upgraded.
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "user",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("email", sa.String(length=150), nullable=False, unique=True),
        sa.Column("password", sa.String(length=255), nullable=False),
        sa.Column("guardian_mode", sa.Boolean(), default=True),
        sa.Column("created_at", sa.DateTime()),
    )
    op.create_table(
        "scan",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("channel", sa.String(length=50), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("threat_type", sa.String(length=100)),
        sa.Column("scam_category", sa.String(length=100)),
        sa.Column("risk_score", sa.Integer(), default=0),
        sa.Column("threat_level", sa.String(length=50)),
        sa.Column("recommendation", sa.Text()),
        sa.Column("created_at", sa.DateTime()),
    )


def downgrade():
    op.drop_table("scan")
    op.drop_table("user")
