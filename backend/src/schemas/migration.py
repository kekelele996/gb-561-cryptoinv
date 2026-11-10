"""迁移清单 schema。"""
from __future__ import annotations

from pydantic import BaseModel, Field


class MigrationTransitionRequest(BaseModel):
    to_status: str = Field(min_length=3, max_length=20)


class MigrationGenerateRequest(BaseModel):
    dry_run: bool = False
