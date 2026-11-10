"""时间与时效工具：所有对外时间统一 UTC-aware，序列化为 ISO8601（Z 后缀）。"""
from __future__ import annotations

from datetime import datetime, timezone

from src.constants.enums import ExpiryBucket

# 批次锚定日：fixtures 与 seed 的证书有效期都围绕这一天设计，
# 看板四档计数 = 运行时 now() 与 not_after 的实时差。
CERT_ANCHOR_DATE = datetime(2026, 11, 10, tzinfo=timezone.utc)

SOON_30_DAYS = 30
SOON_90_DAYS = 90


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def iso(value: datetime | None) -> str | None:
    dt = as_utc(value)
    if dt is None:
        return None
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def days_left(not_after: datetime | None, now: datetime | None = None) -> int | None:
    """剩余有效天数（向下取整，可为负）。"""
    na = as_utc(not_after)
    if na is None:
        return None
    base = now or utcnow()
    return (na - base).days


def expiry_bucket(not_after: datetime | None, now: datetime | None = None) -> str:
    """时效四档：已过期 / ≤30 天 / ≤90 天 / 正常。"""
    left = days_left(not_after, now)
    if left is None:
        return ExpiryBucket.NORMAL.value
    if left < 0:
        return ExpiryBucket.EXPIRED.value
    if left <= SOON_30_DAYS:
        return ExpiryBucket.SOON_30.value
    if left <= SOON_90_DAYS:
        return ExpiryBucket.SOON_90.value
    return ExpiryBucket.NORMAL.value


def validity_ratio(not_before: datetime | None, not_after: datetime | None, now: datetime | None = None) -> float:
    """有效期进度 0..1（详情页有效期条用）：已过期固定 1.0。"""
    nb = as_utc(not_before)
    na = as_utc(not_after)
    if nb is None or na is None or na <= nb:
        return 1.0
    base = now or utcnow()
    if base >= na:
        return 1.0
    if base <= nb:
        return 0.0
    return round((base - nb).total_seconds() / (na - nb).total_seconds(), 4)
