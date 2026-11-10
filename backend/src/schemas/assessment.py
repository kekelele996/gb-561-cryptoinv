"""评估批次 schema。"""
from __future__ import annotations

from pydantic import BaseModel


class AssessmentRunRequest(BaseModel):
    mode: str = "auto"  # auto / worker / inline
