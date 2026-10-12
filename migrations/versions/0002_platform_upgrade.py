"""platform upgrade: new scan columns, token_version, user_settings

Revision ID: 0002_platform_upgrade
Revises: 0001_baseline
Create Date: 2026-01-01 00:00:01

Adds the columns required by the unified analysis engine and the REST
API, plus per-user settings. Existing rows are preserved: text-channel
scans are back-filled with input_type='text', channel values are
normalised, and all new columns are nullable or defaulted.
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_platform_upgrade"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade():
    # --- user: token version for revocable mobile/API auth tokens ---------
    with op.batch_alter_table("user") as batch_op:
        batch_op.add_column(
            sa.Column("token_version", sa.Integer(), nullable=False, server_default="0")
        )

    # --- scan: columns for the unified engine -----------------------------
    with op.batch_alter_table("scan") as batch_op:
        batch_op.add_column(sa.Column("analysis_id", sa.String(length=64)))
        batch_op.add_column(
            sa.Column("input_type", sa.String(length=20), nullable=False, server_default="text")
        )
        batch_op.add_column(sa.Column("url", sa.Text()))
        batch_op.add_column(sa.Column("payload_type", sa.String(length=50)))
        batch_op.add_column(sa.Column("payload_url", sa.Text()))
        batch_op.add_column(sa.Column("rule_score", sa.Integer()))
        batch_op.add_column(sa.Column("ml_prediction", sa.String(length=20)))
        batch_op.add_column(sa.Column("ml_spam_probability", sa.Float()))
        batch_op.add_column(sa.Column("indicators", sa.JSON()))
        batch_op.add_column(sa.Column("recommendations", sa.JSON()))
        batch_op.add_column(sa.Column("manipulation", sa.JSON()))
        batch_op.add_column(sa.Column("evidence", sa.JSON()))
        batch_op.add_column(sa.Column("explanation", sa.Text()))
        batch_op.add_column(sa.Column("ocr_text", sa.Text()))

    op.create_index("ix_scan_analysis_id", "scan", ["analysis_id"])
    op.create_index("ix_scan_user_id", "scan", ["user_id"])
    op.create_index("ix_scan_created_at", "scan", ["created_at"])
    op.create_index("ix_scan_threat_level", "scan", ["threat_level"])
    op.create_index("ix_scan_risk_score", "scan", ["risk_score"])
    op.create_index("ix_scan_user_created", "scan", ["user_id", "created_at"])

    # Back-fill legacy rows so old data behaves like new data.
    op.execute("UPDATE scan SET input_type = 'text' WHERE input_type IS NULL OR input_type = ''")
    op.execute("UPDATE scan SET rule_score = risk_score WHERE rule_score IS NULL")
    op.execute("UPDATE scan SET analysis_id = 'legacy-' || id WHERE analysis_id IS NULL")

    # --- user_settings ----------------------------------------------------
    op.create_table(
        "user_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False, unique=True),
        sa.Column("notifications_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("save_history", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("retention_days", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime()),
    )


def downgrade():
    op.drop_table("user_settings")

    op.drop_index("ix_scan_user_created", table_name="scan")
    op.drop_index("ix_scan_risk_score", table_name="scan")
    op.drop_index("ix_scan_threat_level", table_name="scan")
    op.drop_index("ix_scan_created_at", table_name="scan")
    op.drop_index("ix_scan_user_id", table_name="scan")
    op.drop_index("ix_scan_analysis_id", table_name="scan")

    with op.batch_alter_table("scan") as batch_op:
        for col in [
            "ocr_text", "explanation", "evidence", "manipulation",
            "recommendations", "indicators", "ml_spam_probability",
            "ml_prediction", "rule_score", "payload_url", "payload_type",
            "url", "input_type", "analysis_id",
        ]:
            batch_op.drop_column(col)

    with op.batch_alter_table("user") as batch_op:
        batch_op.drop_column("token_version")
