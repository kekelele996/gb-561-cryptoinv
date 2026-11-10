"""初始化 cryptoinv 全量表。

Revision ID: 0001_initial
"""
from __future__ import annotations

from alembic import op

from src.models import Base

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    # 台账与矩阵的常用组合索引
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_cert_not_after_algo "
        "ON certificate_assets (not_after, pubkey_algo)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_migration_priority_window "
        "ON migration_items (priority, batch_window)"
    )


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
