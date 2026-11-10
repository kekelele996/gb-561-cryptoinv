"""矩阵 controller：algo × dept 热力矩阵。"""
from __future__ import annotations

from sqlalchemy.orm import Session

from src.models.user import User
from src.services import assessment_service


def matrix(db: Session, user: User, *, dept: str | None = None, metric: str = "avg_score") -> dict:
    return assessment_service.build_matrix(db, user=user, dept=dept, metric=metric)
