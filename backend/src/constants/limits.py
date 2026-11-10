"""限额常量：分页、限流桶、每日配额、PEM 体积。"""
from __future__ import annotations

from src.config.settings import settings
from src.constants.roles import ROLE_ADMIN, ROLE_ENGINEER, ROLE_OWNER

MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 20
MAX_PEM_BYTES = 64 * 1024

RATE_LIMIT_DEFAULT_PER_MINUTE = settings.rate_limit_default_per_minute
RATE_LIMIT_ASSESS_PER_MINUTE = settings.rate_limit_assess_per_minute

# 每角色每日配额（跨进程用 Redis 计数；超限 429 DAILY_QUOTA_EXCEEDED）
DAILY_QUOTA: dict[str, int] = {
    ROLE_ADMIN: 2000,
    ROLE_ENGINEER: 1200,
    ROLE_OWNER: 300,
}

# 每个评估批次最多处理证书数（防止一次全量跑爆）
MAX_CERTS_PER_ASSESSMENT = 500
