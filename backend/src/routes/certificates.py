"""证书台账路由：/api/certificates/*"""
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from src.config.database import get_db
from src.controllers import certificate_controller
from src.middlewares.rate_limit import rate_limit
from src.middlewares.rbac import require_permission
from src.models.user import User
from src.schemas.certificate import BatchImportRequest, CertificateImportRequest

router = APIRouter(prefix="/certificates", tags=["certificates"])


@router.get("")
def list_certificates(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    dept: str | None = None,
    bucket: str | None = None,
    algo: str | None = None,
    risk_tag: str | None = None,
    q: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("certs:read")),
    _rl=rate_limit("default"),
) -> dict:
    return certificate_controller.list_certificates(
        None, db, user,
        page=page, page_size=page_size, dept=dept, bucket=bucket,
        algo=algo, risk_tag=risk_tag, q=q,
    )


@router.get("/summary")
def summary(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("certs:read")),
    _rl=rate_limit("default"),
) -> dict:
    return certificate_controller.summary(db, user)


@router.get("/{cert_id}")
def detail(
    cert_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("certs:read")),
    _rl=rate_limit("default"),
) -> dict:
    return certificate_controller.detail(db, user, cert_id)


@router.post("/import")
def import_one(
    request: Request,
    payload: CertificateImportRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("certs:import")),
    _rl=rate_limit("default"),
) -> dict:
    return certificate_controller.import_one(request, db, user, payload)


@router.post("/import/batch")
def import_batch(
    request: Request,
    payload: BatchImportRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("certs:import")),
    _rl=rate_limit("assess"),
) -> dict:
    return certificate_controller.import_batch(request, db, user, payload)
