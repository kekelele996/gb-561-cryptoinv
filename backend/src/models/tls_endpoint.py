from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base, TimestampMixin, new_uuid, utcnow


class TlsEndpoint(Base, TimestampMixin):
    """对外 TLS 端点（厅局域名 + 端口）。"""

    __tablename__ = "tls_endpoints"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dept: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    system_name: Mapped[str] = mapped_column(String(120), nullable=False)
    # 厅局等级 A/B/C：迁移优先级的 dept_grade 分量来源
    dept_grade: Mapped[str] = mapped_column(String(2), nullable=False, default="B")
    internet_facing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tls_versions: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    cipher_suites: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False, default="medium", index=True)
    # 扫描为「受控模拟」：真实做的事只有「用本地 fixture PEM 真跑 X.509 解析」，见 services/scan_sim.py
    simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
