"""审计日志写入：所有写操作与越权尝试都落一条。"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from src.models.audit_log import AuditLog


def record(
    db: Session,
    *,
    action: str,
    entity_type: str,
    entity_id: str | None = None,
    actor_id: str | None = None,
    payload: dict[str, Any] | None = None,
    ip: str | None = None,
    trace_id: str | None = None,
    actor_kind: str = "user",
) -> AuditLog:
    entry = AuditLog(
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        actor_id=actor_id,
        actor_kind=actor_kind,
        payload_json=payload or {},
        ip=ip,
        trace_id=trace_id,
    )
    db.add(entry)
    # 审计必须落库：controller 在业务成功后调用，这里一并提交本次请求的业务变更
    db.commit()
    return entry
