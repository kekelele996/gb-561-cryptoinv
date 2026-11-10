"""证书与链相关 schema。"""
from __future__ import annotations

from pydantic import BaseModel, Field


class CertificateImportRequest(BaseModel):
    pem: str = Field(min_length=60)
    endpoint_id: str | None = None


class BatchImportRequest(BaseModel):
    pems: list[str] = Field(min_length=1, max_length=50)
    endpoint_id: str | None = None


class ChainQuery(BaseModel):
    validation: str | None = None
