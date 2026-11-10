from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base, new_uuid, utcnow


class ChainRecord(Base):
    """链校验记录：cert_path 是按顺序排列的证书 id（叶子在前）。"""

    __tablename__ = "chain_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True, index=True)
    cert_path: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    chain_length: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    validation: Mapped[str] = mapped_column(String(24), nullable=False, default="is_valid", index=True)
    validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    error_detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
