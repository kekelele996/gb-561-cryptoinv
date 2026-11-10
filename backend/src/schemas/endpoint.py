"""端点 schema。"""
from __future__ import annotations

from pydantic import BaseModel, Field


class EndpointCreateRequest(BaseModel):
    hostname: str = Field(min_length=3, max_length=255)
    port: int = Field(443, ge=1, le=65535)
    ip: str | None = Field(None, max_length=64)
    dept: str = Field(min_length=2, max_length=80)
    system_name: str = Field(min_length=2, max_length=120)
    dept_grade: str = Field("B", pattern="^[ABC]$")
    internet_facing: bool = False
