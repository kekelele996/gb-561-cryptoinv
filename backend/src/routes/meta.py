from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from src.config.database import get_db
from src.controllers import meta_controller
from src.middlewares.rbac import require_permission

router = APIRouter(tags=["meta"])


@router.get("/health")
def health(db: Session = Depends(get_db)) -> dict:
    return meta_controller.health(db)


@router.get("/meta/enums")
def enums() -> dict:
    return meta_controller.enums()


@router.get("/chains")
def chains(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    db: Session = Depends(get_db),
    _user=Depends(require_permission("chains:read")),
) -> dict:
    return meta_controller.chains(db, page=page, page_size=page_size)


@router.get("/audit")
def audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    db: Session = Depends(get_db),
    _user=Depends(require_permission("audit:read")),
) -> dict:
    return meta_controller.audit_logs(db, page=page, page_size=page_size)
