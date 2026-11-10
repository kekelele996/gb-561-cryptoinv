"""导出路由：/api/exports/*（全量导出仅 admin）"""
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from src.config.database import get_db
from src.controllers import export_controller
from src.middlewares.rate_limit import rate_limit
from src.middlewares.rbac import require_permission
from src.models.user import User
from src.schemas.export import ExportCreateRequest

router = APIRouter(prefix="/exports", tags=["exports"])


@router.get("")
def list_exports(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("exports:read")),
    _rl=rate_limit("default"),
) -> dict:
    return export_controller.list_exports(db, user, page=page, page_size=page_size)


@router.post("")
def create_export(
    request: Request,
    payload: ExportCreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("exports:create")),
    _rl=rate_limit("default"),
) -> dict:
    return export_controller.create(request, db, user, payload)


@router.get("/{export_id}/download")
def download(
    request: Request,
    export_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("exports:create")),
    _rl=rate_limit("default"),
) -> Response:
    filename, mimetype, content = export_controller.download(request, db, user, export_id)
    return Response(
        content=content.encode("utf-8"),
        media_type=mimetype,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
