"""端点 controller：列表 / 登记 / 模拟扫描。"""
from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from src.models.user import User
from src.schemas.endpoint import EndpointCreateRequest
from src.services import audit_service, endpoint_service


def list_endpoints(
    db: Session,
    user: User,
    *,
    page: int,
    page_size: int,
    dept: str | None,
    internet_facing: bool | None,
    risk_level: str | None,
    q: str | None,
) -> dict:
    return endpoint_service.list_endpoints(
        db,
        user=user,
        page=page,
        page_size=page_size,
        dept=dept,
        internet_facing=internet_facing,
        risk_level=risk_level,
        q=q,
    )


def create(request: Request, db: Session, user: User, payload: EndpointCreateRequest) -> dict:
    result = endpoint_service.create_endpoint(db, payload.model_dump(), user=user)
    audit_service.record(
        db,
        action="endpoint.create",
        entity_type="TlsEndpoint",
        entity_id=result["id"],
        actor_id=str(user.id),
        payload={"hostname": result["hostname"], "port": result["port"]},
        ip=getattr(request.state, "client_ip", None),
        trace_id=getattr(request.state, "trace_id", None),
    )
    return result


def scan(request: Request, db: Session, user: User, endpoint_id: str) -> dict:
    result = endpoint_service.scan_endpoint(db, endpoint_id=endpoint_id, user=user)
    audit_service.record(
        db,
        action="endpoint.scan",
        entity_type="TlsEndpoint",
        entity_id=endpoint_id,
        actor_id=str(user.id),
        payload={
            "simulated": True,
            "risk_level": result["scan"]["risk_level"],
            "cert_fixture": result["scan"]["cert_fixture"],
        },
        ip=getattr(request.state, "client_ip", None),
        trace_id=getattr(request.state, "trace_id", None),
    )
    return result
