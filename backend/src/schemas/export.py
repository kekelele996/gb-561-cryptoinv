"""导出 schema。"""
from __future__ import annotations

from pydantic import BaseModel, Field


class ExportCreateRequest(BaseModel):
    name: str = Field("", max_length=120)
    scope: str = Field("all", pattern="^(all|dept)$")
    format: str = Field("csv", pattern="^(csv|json)$")
