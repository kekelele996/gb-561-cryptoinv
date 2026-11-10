"""证书台账服务：列表（分页 + 行级数据范围）、详情、四档计数、PEM 导入。

行级数据范围：owner 角色只能看自己厅局（user.dept）的证书；
admin/engineer 全量。列表接口一律分页（BRIEF 硬约束）。
"""
from __future__ import annotations

import math
from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from src.constants import error_codes as codes
from src.constants.enums import Compliance, ExpiryBucket, PubkeyAlgo
from src.constants.limits import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, MAX_PEM_BYTES
from src.models.algorithm_assessment import AlgorithmAssessment
from src.models.certificate_asset import CertificateAsset
from src.models.chain_record import ChainRecord
from src.models.migration_item import MigrationItem
from src.models.tls_endpoint import TlsEndpoint
from src.models.user import User
from src.services.x509_audit import (
    PemPrivateKeyRejected,
    PemUnparsable,
    parse_pem,
)
from src.utils.errors import AppError, not_found
from src.utils.timeutil import days_left, expiry_bucket, iso, utcnow

BUCKET_LABELS = {
    ExpiryBucket.EXPIRED.value: "已过期",
    ExpiryBucket.SOON_30.value: "30 天内",
    ExpiryBucket.SOON_90.value: "90 天内",
    ExpiryBucket.NORMAL.value: "正常",
}

ALGO_LABELS = ("RSA-2048+", "RSA-1024", "ECDSA-P256", "ECDSA-P384", "SM2-SM3", "UNKNOWN")


def algo_label(pubkey_algo: str, key_bits: int | None, sig_algo: str, unsupported: bool) -> str:
    """矩阵/统计用的算法分桶（迁移口径的算法轴）。"""
    if unsupported or (pubkey_algo or "").upper() == PubkeyAlgo.UNKNOWN.value:
        return "UNKNOWN"
    algo = (pubkey_algo or "").upper()
    if algo == PubkeyAlgo.SM2.value:
        return "SM2-SM3"
    if algo == PubkeyAlgo.ECDSA.value:
        return "ECDSA-P384" if (key_bits or 0) >= 384 else "ECDSA-P256"
    if algo == PubkeyAlgo.RSA.value:
        if "SHA1" in (sig_algo or ""):
            return "RSA-SHA1"
        if (key_bits or 0) >= 2048:
            return "RSA-2048+"
        return "RSA-1024"
    return "UNKNOWN"


def dept_scope(user: User) -> str | None:
    """owner -> 本厅局；admin/engineer -> None（全量）。"""
    if user.role == "owner":
        return user.dept
    return None


def clamp_page(page: int, page_size: int) -> tuple[int, int]:
    page = max(1, int(page or 1))
    size = min(max(1, int(page_size or DEFAULT_PAGE_SIZE)), MAX_PAGE_SIZE)
    return page, size


def paged(items: list[Any], total: int, page: int, size: int) -> dict[str, Any]:
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": size,
        "pages": max(1, math.ceil(total / size)) if total else 1,
    }


def _cert_query(db: Session):
    return db.query(CertificateAsset, TlsEndpoint).outerjoin(
        TlsEndpoint, TlsEndpoint.id == CertificateAsset.endpoint_id
    )


def _scope_filter(query, dept: str | None):
    if dept is None:
        return query
    return query.filter(TlsEndpoint.dept == dept)


def list_certificates(
    db: Session,
    *,
    user: User,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    dept: str | None = None,
    bucket: str | None = None,
    algo: str | None = None,
    risk_tag: str | None = None,
    q: str | None = None,
) -> dict[str, Any]:
    page, size = clamp_page(page, page_size)
    scope = dept_scope(user)
    query = _cert_query(db)
    if scope:
        query = _scope_filter(query, scope)
    elif dept:
        query = _scope_filter(query, dept)
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(
            or_(
                CertificateAsset.subject_cn.ilike(like),
                CertificateAsset.issuer_cn.ilike(like),
                CertificateAsset.serial.ilike(like),
                TlsEndpoint.hostname.ilike(like),
            )
        )

    rows = query.all()
    now = utcnow()
    assessment_by_cert = {
        str(a.certificate_id): a for a in db.query(AlgorithmAssessment).all()
    }
    chain_by_endpoint = {str(c.endpoint_id): c for c in db.query(ChainRecord).all()}
    filtered: list[tuple[CertificateAsset, TlsEndpoint | None]] = []
    for cert, endpoint in rows:
        assessment = assessment_by_cert.get(str(cert.id))
        cert_bucket = (
            assessment.expiry_bucket if assessment else expiry_bucket(cert.not_after, now)
        )
        label = algo_label(cert.pubkey_algo, cert.key_bits, cert.sig_algo, cert.unsupported_by_crypto_lib)
        if bucket and cert_bucket != bucket:
            continue
        if algo and label != algo:
            continue
        if risk_tag and (not assessment or risk_tag not in (assessment.risk_tags or [])):
            continue
        filtered.append((cert, endpoint))

    filtered.sort(key=lambda pair: (pair[0].not_after, pair[0].subject_cn))
    total = len(filtered)
    start = (page - 1) * size
    page_rows = filtered[start : start + size]
    items = [
        serialize_cert_row(
            cert,
            endpoint,
            assessment_by_cert.get(str(cert.id)),
            chain_by_endpoint.get(str(cert.endpoint_id)) if cert.endpoint_id else None,
        )
        for cert, endpoint in page_rows
    ]
    return paged(items, total, page, size)


def serialize_cert_row(
    cert: CertificateAsset,
    endpoint: TlsEndpoint | None,
    assessment: AlgorithmAssessment | None,
    chain: ChainRecord | None,
) -> dict[str, Any]:
    now = utcnow()
    bucket = assessment.expiry_bucket if assessment else expiry_bucket(cert.not_after, now)
    return {
        "id": str(cert.id),
        "cert_key": cert.cert_key,
        "subject_cn": cert.subject_cn,
        "issuer_cn": cert.issuer_cn,
        "serial": cert.serial,
        "pubkey_algo": cert.pubkey_algo,
        "key_bits": cert.key_bits,
        "sig_algo": cert.sig_algo,
        "algo_label": algo_label(cert.pubkey_algo, cert.key_bits, cert.sig_algo, cert.unsupported_by_crypto_lib),
        "not_before": iso(cert.not_before),
        "not_after": iso(cert.not_after),
        "days_left": days_left(cert.not_after, now),
        "expiry_bucket": bucket,
        "expiry_label": BUCKET_LABELS.get(bucket, bucket),
        "is_ca": cert.is_ca,
        "is_active": cert.is_active,
        "source": cert.source,
        "sha256": cert.sha256,
        "unsupported_by_crypto_lib": cert.unsupported_by_crypto_lib,
        "dept": endpoint.dept if endpoint else None,
        "system_name": endpoint.system_name if endpoint else None,
        "hostname": endpoint.hostname if endpoint else None,
        "internet_facing": bool(endpoint.internet_facing) if endpoint else None,
        "endpoint_id": str(cert.endpoint_id) if cert.endpoint_id else None,
        "chain_validation": chain.validation if chain else None,
        "strength_score": assessment.strength_score if assessment else None,
        "compliance": assessment.compliance if assessment else None,
        "risk_tags": assessment.risk_tags if assessment else [],
    }


def summary(db: Session, *, user: User) -> dict[str, Any]:
    """台账四档计数（真实按 now 与 not_after 计算）+ 算法/合规分布。"""
    scope = dept_scope(user)
    query = _cert_query(db)
    if scope:
        query = _scope_filter(query, scope)
    rows = query.all()
    assessment_by_cert = {str(a.certificate_id): a for a in db.query(AlgorithmAssessment).all()}
    now = utcnow()
    buckets = {b.value: 0 for b in ExpiryBucket}
    by_algo: dict[str, int] = {}
    by_compliance = {c.value: 0 for c in Compliance}
    total_score = 0.0
    scored = 0
    for cert, _endpoint in rows:
        assessment = assessment_by_cert.get(str(cert.id))
        bucket = assessment.expiry_bucket if assessment else expiry_bucket(cert.not_after, now)
        # 看板永远用实时天数，避免评估批次过期后看板失真
        bucket = expiry_bucket(cert.not_after, now)
        buckets[bucket] = buckets.get(bucket, 0) + 1
        label = algo_label(cert.pubkey_algo, cert.key_bits, cert.sig_algo, cert.unsupported_by_crypto_lib)
        by_algo[label] = by_algo.get(label, 0) + 1
        if assessment:
            by_compliance[assessment.compliance] = by_compliance.get(assessment.compliance, 0) + 1
            total_score += assessment.strength_score
            scored += 1
    return {
        "cert_total": len(rows),
        "buckets": buckets,
        "bucket_labels": BUCKET_LABELS,
        "by_algo": by_algo,
        "by_compliance": by_compliance,
        "avg_score": round(total_score / scored, 2) if scored else 0.0,
        "assessed": scored,
    }


def get_detail(db: Session, *, user: User, cert_id: str) -> dict[str, Any]:
    cert = db.get(CertificateAsset, cert_id)
    if cert is None:
        raise not_found("CertificateAsset", cert_id)
    endpoint = db.get(TlsEndpoint, cert.endpoint_id) if cert.endpoint_id else None
    if dept_scope(user) and endpoint is not None and endpoint.dept != dept_scope(user):
        raise AppError(codes.FORBIDDEN, "无权查看其它厅局的证书", f"dept={endpoint.dept}")
    assessment = (
        db.query(AlgorithmAssessment)
        .filter(AlgorithmAssessment.certificate_id == cert.id)
        .one_or_none()
    )
    chain = (
        db.query(ChainRecord).filter(ChainRecord.endpoint_id == cert.endpoint_id).one_or_none()
        if cert.endpoint_id
        else None
    )
    migration = (
        db.query(MigrationItem).filter(MigrationItem.certificate_id == cert.id).one_or_none()
    )
    now = utcnow()
    return {
        "certificate": {
            "id": str(cert.id),
            "cert_key": cert.cert_key,
            "subject_cn": cert.subject_cn,
            "issuer_cn": cert.issuer_cn,
            "subject_dn": cert.subject_dn,
            "issuer_dn": cert.issuer_dn,
            "san": cert.san,
            "serial": cert.serial,
            "not_before": iso(cert.not_before),
            "not_after": iso(cert.not_after),
            "days_left": days_left(cert.not_after, now),
            "expiry_bucket": expiry_bucket(cert.not_after, now),
            "pubkey_algo": cert.pubkey_algo,
            "key_bits": cert.key_bits,
            "sig_algo": cert.sig_algo,
            "sig_algo_oid": cert.sig_algo_oid,
            "is_ca": cert.is_ca,
            "is_active": cert.is_active,
            "ski": cert.ski,
            "aki": cert.aki,
            "sha256": cert.sha256,
            "source": cert.source,
            "unsupported_by_crypto_lib": cert.unsupported_by_crypto_lib,
            "algo_label": algo_label(cert.pubkey_algo, cert.key_bits, cert.sig_algo, cert.unsupported_by_crypto_lib),
            "pem_sha256": cert.sha256,
        },
        "endpoint": serialize_endpoint(endpoint) if endpoint else None,
        "assessment": serialize_assessment(assessment) if assessment else None,
        "chain": serialize_chain(db, chain) if chain else None,
        "migration": serialize_migration(migration) if migration else None,
    }


def serialize_endpoint(endpoint: TlsEndpoint | None) -> dict[str, Any]:
    if endpoint is None:
        return {}
    return {
        "id": str(endpoint.id),
        "hostname": endpoint.hostname,
        "port": endpoint.port,
        "ip": endpoint.ip,
        "dept": endpoint.dept,
        "system_name": endpoint.system_name,
        "dept_grade": endpoint.dept_grade,
        "internet_facing": endpoint.internet_facing,
        "tls_versions": endpoint.tls_versions,
        "cipher_suites": endpoint.cipher_suites,
        "last_scanned_at": iso(endpoint.last_scanned_at),
        "risk_level": endpoint.risk_level,
        "simulated": endpoint.simulated,
    }


def serialize_assessment(row: AlgorithmAssessment | None) -> dict[str, Any]:
    if row is None:
        return {}
    return {
        "strength_score": row.strength_score,
        "risk_tags": row.risk_tags,
        "compliance": row.compliance,
        "key_strength": row.key_strength,
        "sig_strength": row.sig_strength,
        "validity_strength": row.validity_strength,
        "chain_trust": row.chain_trust,
        "agility": row.agility,
        "expiry_bucket": row.expiry_bucket,
        "days_left": row.days_left,
        "assessed_at": iso(row.assessed_at),
    }


def serialize_chain(db: Session, chain: ChainRecord | None) -> dict[str, Any]:
    if chain is None:
        return {}
    links: list[dict[str, Any]] = []
    for cert_id in chain.cert_path or []:
        cert = db.get(CertificateAsset, cert_id)
        if cert is None:
            links.append({"cert_id": cert_id, "missing": True})
            continue
        links.append(
            {
                "cert_id": str(cert.id),
                "subject_cn": cert.subject_cn,
                "issuer_cn": cert.issuer_cn,
                "is_ca": cert.is_ca,
                "sig_algo": cert.sig_algo,
                "key_bits": cert.key_bits,
                "pubkey_algo": cert.pubkey_algo,
                "not_before": iso(cert.not_before),
                "not_after": iso(cert.not_after),
                "missing": False,
            }
        )
    return {
        "chain_length": chain.chain_length,
        "validation": chain.validation,
        "validated_at": iso(chain.validated_at),
        "error_detail": chain.error_detail,
        "links": links,
    }


def serialize_migration(item: MigrationItem | None) -> dict[str, Any]:
    if item is None:
        return {}
    return {
        "id": str(item.id),
        "target_algo": item.target_algo,
        "priority": item.priority,
        "priority_score": item.priority_score,
        "batch_window": item.batch_window,
        "status": item.status,
        "rationale": item.rationale,
        "planned_at": iso(item.planned_at),
        "done_at": iso(item.done_at),
    }


def import_pem(
    db: Session,
    *,
    pem: str,
    endpoint_id: str | None,
    user: User,
    source: str = "import",
) -> dict[str, Any]:
    """导入 PEM：真解析 -> 拒绝私钥 -> 自然键幂等 upsert。"""
    if len(pem.encode("utf-8")) > MAX_PEM_BYTES:
        raise AppError(codes.VALIDATION_ERROR, "PEM 超过 64KiB 上限", "too large")
    try:
        parsed = parse_pem(pem)
    except PemPrivateKeyRejected as exc:
        raise AppError(codes.PEM_PRIVATE_KEY_REJECTED, None, str(exc)) from exc
    except PemUnparsable as exc:
        raise AppError(codes.PEM_UNPARSABLE, None, f"{exc.reason}: {exc.detail}") from exc

    endpoint = None
    if endpoint_id:
        endpoint = db.get(TlsEndpoint, endpoint_id)
        if endpoint is None:
            raise not_found("TlsEndpoint", endpoint_id)
        if dept_scope(user) and endpoint.dept != dept_scope(user):
            raise AppError(codes.FORBIDDEN, "无权向其它厅局导入证书", f"dept={endpoint.dept}")

    cert_key = f"imp-{parsed.sha256[:16]}"
    existing = db.query(CertificateAsset).filter(CertificateAsset.cert_key == cert_key).one_or_none()
    if existing is not None:
        return {"created": False, "certificate_id": str(existing.id), "cert_key": cert_key}

    cert = CertificateAsset(
        endpoint_id=endpoint.id if endpoint else None,
        cert_key=cert_key,
        pem=pem,
        subject_cn=parsed.subject_cn,
        issuer_cn=parsed.issuer_cn,
        subject_dn=parsed.subject_dn,
        issuer_dn=parsed.issuer_dn,
        san=parsed.san,
        serial=parsed.serial,
        not_before=parsed.not_before,
        not_after=parsed.not_after,
        pubkey_algo=parsed.pubkey_algo,
        key_bits=parsed.key_bits,
        sig_algo=parsed.sig_algo,
        sig_algo_oid=parsed.sig_algo_oid,
        unsupported_by_crypto_lib=parsed.unsupported_by_crypto_lib,
        is_ca=parsed.is_ca,
        ski=parsed.ski,
        aki=parsed.aki,
        sha256=parsed.sha256,
        source=source,
        is_active=True,
    )
    db.add(cert)
    db.flush()
    return {"created": True, "certificate_id": str(cert.id), "cert_key": cert_key}


def unrparsable_report(pem_list: list[str]) -> dict[str, Any]:
    """批量导入时的不可解析清单（`unparsable` 列表）。"""
    ok: list[dict[str, Any]] = []
    unparsable: list[dict[str, Any]] = []
    for index, pem in enumerate(pem_list):
        try:
            parsed = parse_pem(pem)
        except (PemUnparsable, PemPrivateKeyRejected) as exc:
            unparsable.append({"index": index, "reason": type(exc).__name__, "detail": str(exc)})
            continue
        ok.append({"index": index, "sha256": parsed.sha256, "subject_cn": parsed.subject_cn})
    return {"parsed": ok, "unparsable": unparsable}
