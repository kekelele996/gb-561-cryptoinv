from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base, new_uuid, utcnow


class InventoryExport(Base):
    """导出记录（导出审批审计：谁、什么范围、多少行、什么格式）。"""

    __tablename__ = "inventory_exports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(10), nullable=False, default="all")
    export_format: Mapped[str] = mapped_column(String(10), nullable=False, default="csv")
    rows: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    filters: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    generated_by: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
