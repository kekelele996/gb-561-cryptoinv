from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base, new_uuid, utcnow


class MigrationItem(Base):
    """国密/强算法迁移清单项。priority_score 与 priority 都是算法 2 的真实输出。"""

    __tablename__ = "migration_items"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    certificate_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True, index=True)
    target_algo: Mapped[str] = mapped_column(String(20), nullable=False, default="SM2-SM3")
    priority: Mapped[str] = mapped_column(String(4), nullable=False, default="P2", index=True)
    priority_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, index=True)
    batch_window: Mapped[str] = mapped_column(String(10), nullable=False, default="2027Q1", index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="todo", index=True)
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    planned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
