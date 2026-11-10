"""导出 controller：创建全量导出（审批）、列表、下载。"""
from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from src.models.user import User
from src.schemas.export import ExportCreateRequest
from src.services import audit_service, export_service


def create(request: Request, db: Session, user: User, payload: ExportCreateRequest) -> dict:
    result = export_service.create_export(
        db,
        user=user,
        name=payload.name,
        scope=payload.scope,
        export_format=payload.format,
    )
    audit_service.record(
        db,
        action="export.create",
        entity_type="InventoryExport",
        entity_id=result["id"],
        actor_id=str(user.id),
        payload={"rows": result["rows"], "format": payload.format, "scope": payload.scope},
        ip=getattr(request.state, "client_ip", None),
        trace_id=getattr(request.state, "trace_id", None),
    )
    return result


def list_exports(db: Session, user: User, *, page: int, page_size: int) -> dict:
    return export_service.list_exports(db, user=user, page=page, page_size=page_size)


def download(request: Request, db: Session, user: User, export_id: str) -> tuple[str, str, str]:
    filename, mimetype, content = export_service.download(db, export_id=export_id, user=user)
    audit_service.record(
        db,
        action="export.download",
        entity_type="InventoryExport",
        entity_id=export_id,
        actor_id=str(user.id),
        payload={"rows": content.count("\n") - 1, "filename": filename},
        ip=getattr(request.state, "client_ip", None),
        trace_id=getattr(request.state, "trace_id", None),
    )
    return filename, mimetype, content
