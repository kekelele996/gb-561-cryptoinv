"""ASGI 审计上下文中间件：trace_id、耗时、客户端 IP。

只往 request.state 塞上下文；业务成功后的落库由 controller 显式调
audit_service.record（这样能带上 entity_id）。
"""
from __future__ import annotations

import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from src.utils.logger import get_logger

logger = get_logger("cryptoinv.access")


class AuditContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        trace_id = request.headers.get("x-trace-id") or uuid.uuid4().hex[:16]
        request.state.trace_id = trace_id
        request.state.client_ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "")
        )
        request.state.actor_kind = "user"
        started = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        response.headers["x-trace-id"] = trace_id
        if request.url.path not in ("/health", "/api/health"):
            logger.info(
                "%s %s -> %s %sms trace=%s",
                request.method,
                request.url.path,
                response.status_code,
                elapsed_ms,
                trace_id,
            )
        return response
