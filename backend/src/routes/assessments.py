"""评估路由：/api/assessments/*"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from src.config.database import get_db
from src.controllers import assessment_controller
from src.middlewares.rate_limit import rate_limit
from src.middlewares.rbac import require_permission
from src.models.user import User
from src.schemas.assessment import AssessmentRunRequest

router = APIRouter(prefix="/assessments", tags=["assessments"])


@router.post("/run")
def run_assessment(
    request: Request,
    payload: AssessmentRunRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assessments:run")),
    _rl=rate_limit("assess"),
) -> dict:
    return assessment_controller.run(request, db, user, mode=payload.mode)


@router.get("/runs/{run_id}")
def run_status(
    run_id: str,
    user: User = Depends(require_permission("assessments:read")),
) -> dict:
    return assessment_controller.run_status(run_id)


@router.get("/summary")
def summary(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("assessments:read")),
    _rl=rate_limit("default"),
) -> dict:
    return assessment_controller.summary(db, user)
