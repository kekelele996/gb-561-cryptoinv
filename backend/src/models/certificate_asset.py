from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base, new_uuid, utcnow


class CertificateAsset(Base):
    """证书资产。**只存证书 PEM（公钥部分）；私钥在导入时即被拒绝，绝不入库。**

    `cert_key` 是 seed / 导入的自然键（稳定字符串），重复导入幂等。
    """

    __tablename__ = "certificate_assets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    # 链上的 CA 证书没有 endpoint（import 进来的 CA 材料），叶子证书一般有
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    cert_key: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    pem: Mapped[str] = mapped_column(Text, nullable=False)
    subject_cn: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    issuer_cn: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    subject_dn: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    issuer_dn: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    san: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    serial: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    pubkey_algo: Mapped[str] = mapped_column(String(20), nullable=False, default="RSA", index=True)
    key_bits: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sig_algo: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    sig_algo_oid: Mapped[str] = mapped_column(String(60), nullable=False, default="")
    # cryptography 不支持的曲线（如 SM2）记录为 true —— 诚实边界
    unsupported_by_crypto_lib: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_ca: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ski: Mapped[str | None] = mapped_column(String(80), nullable=True)
    aki: Mapped[str | None] = mapped_column(String(80), nullable=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="import")
    # 是否该端点当前生效的叶证书（历史证书保留为 False，仍参与评估）
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
