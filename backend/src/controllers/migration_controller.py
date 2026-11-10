"""迁移 controller：清单 / 生成 / 状态流转 / 导出 CSV。"""
from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from src.models.user import User
from src.schemas.migration import MigrationTransitionRequest
from src.services import audit_service, export_service, migration_service


def list_items(
    db: Session,
    user: User,
    *,
    page: int,
    page_size: int,
    priority: str | None,
    status: str | None,
    window: str | None,
    dept: str | None,
) -> dict:
    return migration_service.list_items(
        db,
        user=user,
        page=page,
        page_size=page_size,
        priority=priority,
        status=status,
        window=window,
        dept=dept,
    )


def generate(request: Request, db: Session, user: User, dry_run: bool = False) -> dict:
    result = migration_service.generate(db, user=user)
    if not dry_run:
        audit_service.record(
            db,
            action="migration.generate",
            entity_type="MigrationItem",
            actor_id=str(user.id),
            payload={"created": result["created"], "refreshed": result["refreshed"]},
            ip=getattr(request.state, "client_ip", None),
            trace_id=getattr(request.state, "trace_id", None),
        )
    return result


def transition(request: Request, db: Session, user: User, item_id: str, payload: MigrationTransitionRequest) -> dict:
    result = migration_service.transition(db, item_id=item_id, to_status=payload.to_status, user=user)
    audit_service.record(
        db,
        action="migration.transition",
        entity_type="MigrationItem",
        entity_id=item_id,
        actor_id=str(user.id),
        payload={"status": result["status"]},
        ip=getattr(request.state, "client_ip", None),
        trace_id=getattr(request.state, "trace_id", None),
    )
    return result


def export_csv(
    request: Request, db: Session, user: User, *, dept: str | None, priority: str | None
) -> tuple[str, str]:
    filename, content = export_service.migration_csv(db, user=user, dept=dept, priority=priority)
    audit_service.record(
        db,
        action="migration.export",
        entity_type="MigrationItem",
        actor_id=str(user.id),
        payload={"dept": dept, "priority": priority, "rows": content.count("\n") - 1},
        ip=getattr(request.state, "client_ip", None),
        trace_id=getattr(request.state, "trace_id", None),
    )
    return filename, content
