"""端点路由：/api/endpoints/*"""
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from src.config.database import get_db
from src.controllers import endpoint_controller
from src.middlewares.rate_limit import rate_limit
from src.middlewares.rbac import require_permission
from src.models.user import User
from src.schemas.endpoint import EndpointCreateRequest

router = APIRouter(prefix="/endpoints", tags=["endpoints"])


@router.get("")
def list_endpoints(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    dept: str | None = None,
    internet_facing: bool | None = None,
    risk_level: str | None = None,
    q: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("endpoints:read")),
    _rl=rate_limit("default"),
) -> dict:
    return endpoint_controller.list_endpoints(
        db, user,
        page=page, page_size=page_size, dept=dept,
        internet_facing=internet_facing, risk_level=risk_level, q=q,
    )


@router.post("")
def create_endpoint(
    request: Request,
    payload: EndpointCreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("endpoints:scan")),
    _rl=rate_limit("default"),
) -> dict:
    return endpoint_controller.create(request, db, user, payload)


@router.post("/{endpoint_id}/scan")
def scan_endpoint(
    request: Request,
    endpoint_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("endpoints:scan")),
    _rl=rate_limit("assess"),
) -> dict:
    return endpoint_controller.scan(request, db, user, endpoint_id)
