"""RBAC：三角色 admin / engineer / owner。

前后端必须一致：users.role / constants/roles.py / frontend/constants/enums.ts（UserRole）。
owner 只读「本厅局」数据 —— 服务层用 user.dept 做行级过滤，见 services/certificate_service。
"""
from __future__ import annotations

ROLE_ADMIN = "admin"
ROLE_ENGINEER = "engineer"
ROLE_OWNER = "owner"

ALL_ROLES: tuple[str, ...] = (ROLE_ADMIN, ROLE_ENGINEER, ROLE_OWNER)

PERMISSIONS: dict[str, tuple[str, ...]] = {
    "certs:read": ALL_ROLES,
    "certs:import": (ROLE_ADMIN, ROLE_ENGINEER),
    "endpoints:read": ALL_ROLES,
    "endpoints:scan": (ROLE_ADMIN, ROLE_ENGINEER),
    "chains:read": ALL_ROLES,
    "assessments:read": ALL_ROLES,
    "assessments:run": (ROLE_ADMIN, ROLE_ENGINEER),
    "matrix:read": ALL_ROLES,
    "migration:read": ALL_ROLES,
    "migration:generate": (ROLE_ADMIN, ROLE_ENGINEER),
    # owner 可以「确认迁移窗口」（改自己厅局迁移项的状态）
    "migration:update": ALL_ROLES,
    "exports:read": ALL_ROLES,
    # 全量导出 = 导出审批能力，只给 admin（owner 尝试 -> 403）
    "exports:create": (ROLE_ADMIN,),
    "migration:export": (ROLE_ADMIN, ROLE_ENGINEER),
    "audit:read": (ROLE_ADMIN,),
    "users:admin": (ROLE_ADMIN,),
}

ROLE_LABELS = {
    ROLE_ADMIN: "密码应用中心管理员",
    ROLE_ENGINEER: "密码资产工程师",
    ROLE_OWNER: "厅局资产责任人",
}


def role_can(role: str, action: str) -> bool:
    return role in PERMISSIONS.get(action, ())


def role_permissions(role: str) -> list[str]:
    return [action for action, roles in PERMISSIONS.items() if role in roles]
