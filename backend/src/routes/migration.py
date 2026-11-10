"""迁移清单路由：/api/migration/*"""
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from src.config.database import get_db
from src.controllers import migration_controller
from src.middlewares.rate_limit import rate_limit
from src.middlewares.rbac import require_permission
from src.models.user import User
from src.schemas.migration import MigrationGenerateRequest, MigrationTransitionRequest

router = APIRouter(prefix="/migration", tags=["migration"])


@router.get("")
def list_items(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    priority: str | None = None,
    status: str | None = None,
    window: str | None = None,
    dept: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("migration:read")),
    _rl=rate_limit("default"),
) -> dict:
    return migration_controller.list_items(
        db, user,
        page=page, page_size=page_size, priority=priority,
        status=status, window=window, dept=dept,
    )


@router.post("/generate")
def generate(
    request: Request,
    payload: MigrationGenerateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("migration:generate")),
    _rl=rate_limit("assess"),
) -> dict:
    return migration_controller.generate(request, db, user, dry_run=payload.dry_run)


@router.post("/{item_id}/transition")
def transition(
    request: Request,
    item_id: str,
    payload: MigrationTransitionRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("migration:update")),
    _rl=rate_limit("default"),
) -> dict:
    return migration_controller.transition(request, db, user, item_id, payload)


@router.get("/export.csv")
def export_csv(
    request: Request,
    dept: str | None = None,
    priority: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("migration:export")),
    _rl=rate_limit("default"),
) -> Response:
    filename, content = migration_controller.export_csv(
        request, db, user, dept=dept, priority=priority
    )
    return Response(
        content=content.encode("utf-8-sig"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
