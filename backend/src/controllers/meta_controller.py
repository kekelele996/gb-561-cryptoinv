"""meta controller：健康检查、枚举字典、审计日志查询。"""
from __future__ import annotations

from fastapi import Depends
from sqlalchemy.orm import Session

from src.config.database import get_db, ping_db
from src.constants.enums import (
    BatchWindow,
    ChainValidation,
    Compliance,
    ExpiryBucket,
    MigrationPriority,
    MigrationStatus,
    MigrationTarget,
    RiskTag,
)
from src.constants.limits import DEFAULT_PAGE_SIZE
from src.models.audit_log import AuditLog
from src.models.certificate_asset import CertificateAsset
from src.models.chain_record import ChainRecord
from src.models.tls_endpoint import TlsEndpoint
from src.services.certificate_service import clamp_page, paged
from src.utils.redis_client import get_redis
from src.utils.timeutil import iso

ENUM_DICTIONARY = {
    "migration_priority": [p.value for p in MigrationPriority],
    "chain_validation": [v.value for v in ChainValidation],
    "risk_tag": [t.value for t in RiskTag],
    "compliance": [c.value for c in Compliance],
    "expiry_bucket": [b.value for b in ExpiryBucket],
    "migration_status": [s.value for s in MigrationStatus],
    "migration_target": [t.value for t in MigrationTarget],
    "batch_window": [w.value for w in BatchWindow],
}


def health(db: Session = Depends(get_db)) -> dict:
    redis_ok = True
    try:
        get_redis().ping()
    except Exception:  # noqa: BLE001
        redis_ok = False
    return {"status": "ok", "service": "cryptoinv-backend", "db": ping_db(), "redis": redis_ok}


def enums() -> dict:
    return ENUM_DICTIONARY


def audit_logs(db: Session, *, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE) -> dict:
    page, size = clamp_page(page, page_size)
    query = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    total = query.count()
    rows = query.offset((page - 1) * size).limit(size).all()
    items = [
        {
            "id": str(row.id),
            "action": row.action,
            "entity_type": row.entity_type,
            "entity_id": row.entity_id,
            "actor_id": str(row.actor_id) if row.actor_id else None,
            "payload": row.payload_json,
            "ip": row.ip,
            "trace_id": row.trace_id,
            "created_at": iso(row.created_at),
        }
        for row in rows
    ]
    return paged(items, total, page, size)


def chains(db: Session, *, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE) -> dict:
    """链校验记录列表（端点维度）：验证结论、链长、证书路径。"""
    page, size = clamp_page(page, page_size)
    query = db.query(ChainRecord).order_by(ChainRecord.validated_at.desc())
    total = query.count()
    rows = query.offset((page - 1) * size).limit(size).all()
    endpoint_map = {str(e.id): e for e in db.query(TlsEndpoint).all()}
    cert_map = {str(c.id): c for c in db.query(CertificateAsset).all()}
    items = []
    for row in rows:
        endpoint = endpoint_map.get(str(row.endpoint_id))
        path = [
            {
                "cert_id": cert_id,
                "subject_cn": cert_map[cert_id].subject_cn if cert_id in cert_map else None,
                "is_ca": cert_map[cert_id].is_ca if cert_id in cert_map else None,
            }
            for cert_id in (row.cert_path or [])
        ]
        items.append(
            {
                "id": str(row.id),
                "endpoint_id": str(row.endpoint_id),
                "hostname": endpoint.hostname if endpoint else None,
                "dept": endpoint.dept if endpoint else None,
                "chain_length": row.chain_length,
                "validation": row.validation,
                "error_detail": row.error_detail,
                "validated_at": iso(row.validated_at),
                "cert_path": path,
            }
        )
    return paged(items, total, page, size)
