"""证书 controller：台账列表 / 四档汇总 / 详情 / PEM 导入（含 unparsable 清单）。"""
from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from src.models.user import User
from src.schemas.certificate import BatchImportRequest, CertificateImportRequest
from src.services import audit_service, certificate_service


def list_certificates(
    request: Request,
    db: Session,
    user: User,
    *,
    page: int,
    page_size: int,
    dept: str | None,
    bucket: str | None,
    algo: str | None,
    risk_tag: str | None,
    q: str | None,
) -> dict:
    return certificate_service.list_certificates(
        db,
        user=user,
        page=page,
        page_size=page_size,
        dept=dept,
        bucket=bucket,
        algo=algo,
        risk_tag=risk_tag,
        q=q,
    )


def summary(db: Session, user: User) -> dict:
    return certificate_service.summary(db, user=user)


def detail(db: Session, user: User, cert_id: str) -> dict:
    return certificate_service.get_detail(db, user=user, cert_id=cert_id)


def import_one(request: Request, db: Session, user: User, payload: CertificateImportRequest) -> dict:
    result = certificate_service.import_pem(
        db, pem=payload.pem, endpoint_id=payload.endpoint_id, user=user
    )
    audit_service.record(
        db,
        action="certificate.import",
        entity_type="CertificateAsset",
        entity_id=result["certificate_id"],
        actor_id=str(user.id),
        payload={"created": result["created"], "source": "import"},
        ip=getattr(request.state, "client_ip", None),
        trace_id=getattr(request.state, "trace_id", None),
    )
    return result


def import_batch(request: Request, db: Session, user: User, payload: BatchImportRequest) -> dict:
    parsed: list[dict] = []
    unparsable: list[dict] = []
    created = 0
    for index, pem in enumerate(payload.pems):
        try:
            result = certificate_service.import_pem(
                db, pem=pem, endpoint_id=payload.endpoint_id, user=user, source="import"
            )
            parsed.append({"index": index, **result})
            created += 1 if result["created"] else 0
        except Exception as exc:  # noqa: BLE001 - 单条失败不影响其它条
            db.rollback()
            unparsable.append({"index": index, "reason": type(exc).__name__, "detail": str(exc)})
    audit_service.record(
        db,
        action="certificate.import_batch",
        entity_type="CertificateAsset",
        actor_id=str(user.id),
        payload={"created": created, "unparsable": len(unparsable)},
        ip=getattr(request.state, "client_ip", None),
        trace_id=getattr(request.state, "trace_id", None),
    )
    return {"parsed": parsed, "unparsable": unparsable, "created": created}
