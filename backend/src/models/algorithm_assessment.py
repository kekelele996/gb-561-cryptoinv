from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base, new_uuid, utcnow


class AlgorithmAssessment(Base):
    """算法强度评估结果（算法 2 落库点）。"""

    __tablename__ = "algorithm_assessments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    certificate_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    strength_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, index=True)
    risk_tags: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    compliance: Mapped[str] = mapped_column(String(20), nullable=False, default="compliant", index=True)
    # 五个分量都落库，便于复核评分可解释性
    key_strength: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    sig_strength: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    validity_strength: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    chain_trust: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    agility: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    expiry_bucket: Mapped[str] = mapped_column(String(20), nullable=False, default="normal", index=True)
    days_left: Mapped[int | None] = mapped_column(Integer, nullable=True)
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
