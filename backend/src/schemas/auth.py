"""认证相关 schema。"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    # 演示域名不是真实可投递域名，这里用普通字符串而不是 EmailStr（避免 email-validator 拒绝 .demo）
    email: str = Field(min_length=5, max_length=200)
    password: str = Field(min_length=6, max_length=128)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10)


def serialize_user(user: Any) -> dict[str, Any]:
    return {
        "id": str(user.id),
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "dept": user.dept,
        "is_active": user.is_active,
    }
