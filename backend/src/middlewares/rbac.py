"""RBAC：require_role(*roles) / require_permission(action)，并给越权尝试写审计。"""
from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from src.config.database import get_db
from src.constants import error_codes as codes
from src.constants.roles import role_can
from src.middlewares.auth import get_current_user
from src.models.user import User
from src.services import audit_service
from src.utils.errors import AppError


def _deny(
    request: Request,
    db: Session,
    user: User,
    reason: str,
    action: str,
    message: str,
) -> None:
    """越权尝试落审计（不吞异常，仍然抛 403）。"""
    try:
        audit_service.record(
            db,
            action="authz.denied",
            entity_type="Route",
            entity_id=f"{request.method} {request.url.path}",
            actor_id=str(user.id),
            payload={"reason": reason, "required": action, "role": user.role},
            ip=getattr(request.state, "client_ip", None),
            trace_id=getattr(request.state, "trace_id", None),
        )
        db.commit()
    except Exception:  # noqa: BLE001 - 审计失败不能改变 403 结论
        db.rollback()
    raise AppError(codes.FORBIDDEN, message, reason)


def require_role(*roles: str) -> Callable[..., User]:
    allowed = tuple(roles)

    def dependency(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
        if user.role not in allowed:
            _deny(
                request,
                db,
                user,
                f"role={user.role} required={allowed}",
                "role",
                f"当前角色（{user.role}）无权执行该操作",
            )
        return user

    return dependency


def require_permission(action: str) -> Callable[..., User]:
    def dependency(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
        if not role_can(user.role, action):
            _deny(
                request,
                db,
                user,
                f"role={user.role} action={action}",
                action,
                f"当前角色（{user.role}）无 {action} 权限",
            )
        return user

    return dependency
