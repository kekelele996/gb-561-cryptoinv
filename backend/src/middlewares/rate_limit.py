"""限流 + 每日配额（Redis 滑动窗口 / 日计数器），超限 429。

两个桶：
  * per-user-per-minute：按 (bucket, user_id, path) 滑动窗口，削峰；
  * per-role-per-day   ：按 (role, date) 每日配额，跨进程共享。
"""
from __future__ import annotations

import time
from datetime import date

from fastapi import Depends, Request

from src.constants import error_codes as codes
from src.constants.limits import (
    DAILY_QUOTA,
    RATE_LIMIT_ASSESS_PER_MINUTE,
    RATE_LIMIT_DEFAULT_PER_MINUTE,
)
from src.middlewares.auth import get_current_user
from src.models.user import User
from src.utils.errors import AppError
from src.utils.redis_client import get_redis


def _minute_check(key: str, limit: int, window_seconds: int = 60) -> int:
    now = time.time()
    client = get_redis()
    pipeline = client.pipeline()
    pipeline.zremrangebyscore(key, 0, now - window_seconds)
    pipeline.zadd(key, {f"{now}": now})
    pipeline.zcard(key)
    pipeline.expire(key, window_seconds)
    results = pipeline.execute()
    count = int(results[2])
    if count > limit:
        raise AppError(
            codes.RATE_LIMITED,
            "请求过于频繁，请稍后重试",
            f"key={key} count={count} limit={limit}",
            extra={"retry_after": window_seconds},
        )
    return count


def _daily_quota_check(user: User) -> None:
    limit = DAILY_QUOTA.get(user.role)
    if not limit:
        return
    key = f"cryptoinv:quota:{user.role}:{date.today().isoformat()}"
    client = get_redis()
    try:
        count = client.incr(key)
        if count == 1:
            client.expire(key, 86400 * 2)
    except Exception:  # noqa: BLE001 - Redis 不可用时降级放行（限流不应让服务不可用）
        return
    if count > limit:
        raise AppError(
            codes.DAILY_QUOTA_EXCEEDED,
            None,
            f"role={user.role} count={count} limit={limit}",
            extra={"limit": limit, "used": count},
        )


def rate_limit(bucket: str = "default"):
    limit = RATE_LIMIT_ASSESS_PER_MINUTE if bucket == "assess" else RATE_LIMIT_DEFAULT_PER_MINUTE

    def dependency(request: Request, user: User = Depends(get_current_user)) -> None:
        _minute_check(f"cryptoinv:ratelimit:{bucket}:{user.id}:{request.url.path}", limit)
        _daily_quota_check(user)

    return Depends(dependency)
