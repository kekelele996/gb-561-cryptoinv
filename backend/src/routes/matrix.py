"""算法风险矩阵路由。"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.config.database import get_db
from src.controllers import matrix_controller
from src.middlewares.rate_limit import rate_limit
from src.middlewares.rbac import require_permission
from src.models.user import User

router = APIRouter(prefix="/matrix", tags=["matrix"])


@router.get("")
def matrix(
    dept: str | None = None,
    metric: str = "avg_score",
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("matrix:read")),
    _rl=rate_limit("default"),
) -> dict:
    return matrix_controller.matrix(db, user, dept=dept, metric=metric)
