"""端点服务：列表（分页 + 厅局范围）、创建、受控模拟扫描落库。"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from src.config.settings import settings
from src.constants import error_codes as codes
from src.constants.enums import CertSource, EndpointRisk, ExpiryBucket
from src.constants.limits import DEFAULT_PAGE_SIZE
from src.models.algorithm_assessment import AlgorithmAssessment
from src.models.certificate_asset import CertificateAsset
from src.models.chain_record import ChainRecord
from src.models.tls_endpoint import TlsEndpoint
from src.models.user import User
from src.services import assessment_service
from src.services.certificate_service import (
    clamp_page,
    dept_scope,
    paged,
    serialize_cert_row,
    serialize_chain,
)
from src.services.x509_audit import parse_pem
from src.utils.errors import AppError, not_found
from src.utils.logger import get_logger
from src.utils.timeutil import iso, utcnow

logger = get_logger("cryptoinv.endpoint")


def list_endpoints(
    db: Session,
    *,
    user: User,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    dept: str | None = None,
    internet_facing: bool | None = None,
    risk_level: str | None = None,
    q: str | None = None,
) -> dict[str, Any]:
    page, size = clamp_page(page, page_size)
    scope = dept_scope(user)
    query = db.query(TlsEndpoint)
    if scope:
        query = query.filter(TlsEndpoint.dept == scope)
    elif dept:
        query = query.filter(TlsEndpoint.dept == dept)
    if internet_facing is not None:
        query = query.filter(TlsEndpoint.internet_facing.is_(internet_facing))
    if risk_level:
        query = query.filter(TlsEndpoint.risk_level == risk_level)
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(or_(TlsEndpoint.hostname.ilike(like), TlsEndpoint.system_name.ilike(like)))

    rows = query.order_by(TlsEndpoint.dept, TlsEndpoint.hostname).all()
    total = len(rows)
    start = (page - 1) * size
    chain_by_endpoint = {str(c.endpoint_id): c for c in db.query(ChainRecord).all()}
    cert_count = {
        str(cert.endpoint_id): 0
        for cert in db.query(CertificateAsset).filter(CertificateAsset.endpoint_id.isnot(None)).all()
    }
    for cert in db.query(CertificateAsset).filter(CertificateAsset.endpoint_id.isnot(None)).all():
        cert_count[str(cert.endpoint_id)] = cert_count.get(str(cert.endpoint_id), 0) + 1

    items = []
    for endpoint in rows[start : start + size]:
        chain = chain_by_endpoint.get(str(endpoint.id))
        items.append(
            {
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
                "cert_count": cert_count.get(str(endpoint.id), 0),
                "chain_validation": chain.validation if chain else None,
                "chain_length": chain.chain_length if chain else 0,
            }
        )
    return {
        **paged(items, total, page, size),
        "summary": endpoint_summary(db, user=user),
    }


def endpoint_summary(db: Session, *, user: User) -> dict[str, Any]:
    scope = dept_scope(user)
    query = db.query(TlsEndpoint)
    if scope:
        query = query.filter(TlsEndpoint.dept == scope)
    rows = query.all()
    by_risk = {r.value: 0 for r in EndpointRisk}
    for row in rows:
        by_risk[row.risk_level] = by_risk.get(row.risk_level, 0) + 1
    return {
        "total": len(rows),
        "internet_facing": sum(1 for r in rows if r.internet_facing),
        "scanned": sum(1 for r in rows if r.last_scanned_at is not None),
        "by_risk": by_risk,
    }


def create_endpoint(db: Session, payload: dict[str, Any], *, user: User) -> dict[str, Any]:
    scope = dept_scope(user)
    if scope and payload.get("dept") != scope:
        raise AppError(codes.FORBIDDEN, "无权在其它厅局登记端点", f"dept={payload.get('dept')}")
    exists = (
        db.query(TlsEndpoint)
        .filter(
            TlsEndpoint.hostname == payload["hostname"].strip().lower(),
            TlsEndpoint.port == int(payload.get("port", 443)),
        )
        .one_or_none()
    )
    if exists is not None:
        raise AppError(codes.ENDPOINT_EXISTS, None, f"hostname={payload['hostname']}")
    endpoint = TlsEndpoint(
        hostname=payload["hostname"].strip().lower(),
        port=int(payload.get("port", 443)),
        ip=payload.get("ip"),
        dept=payload["dept"],
        system_name=payload["system_name"],
        dept_grade=(payload.get("dept_grade") or "B").upper(),
        internet_facing=bool(payload.get("internet_facing", False)),
        tls_versions=[],
        cipher_suites=[],
        risk_level=EndpointRisk.MEDIUM.value,
        simulated=True,
    )
    db.add(endpoint)
    db.flush()
    return {"id": str(endpoint.id), "hostname": endpoint.hostname, "port": endpoint.port}


def scan_endpoint(db: Session, *, endpoint_id: str, user: User) -> dict[str, Any]:
    """受控模拟扫描：确定性挑选本地 fixture PEM -> 真解析 -> 落库 -> 全量重算链/评分。"""
    endpoint = db.get(TlsEndpoint, endpoint_id)
    if endpoint is None:
        raise not_found("TlsEndpoint", endpoint_id)
    scope = dept_scope(user)
    if scope and endpoint.dept != scope:
        raise AppError(codes.FORBIDDEN, "无权扫描其它厅局的端点", f"dept={endpoint.dept}")

    scan = simulate_scan(endpoint.hostname, endpoint.port, endpoint.internet_facing)
    certificate_payload: dict[str, Any] | None = None
    parsed_error: str | None = None

    if scan.pem:
        try:
            parsed = parse_pem(scan.pem)
            # 同一端点再次扫描：把旧证书标为非生效（历史保留），新证书设为生效
            db.query(CertificateAsset).filter(
                CertificateAsset.endpoint_id == endpoint.id,
                CertificateAsset.is_active.is_(True),
                CertificateAsset.is_ca.is_(False),
            ).update({CertificateAsset.is_active: False}, synchronize_session=False)
            cert_key = f"scan-{endpoint.hostname}-{endpoint.port}-{parsed.sha256[:12]}"
            cert = (
                db.query(CertificateAsset)
                .filter(CertificateAsset.cert_key == cert_key)
                .one_or_none()
            )
            if cert is None:
                cert = CertificateAsset(
                    cert_key=cert_key,
                    pem=scan.pem,
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
                    source=CertSource.SCAN.value,
                )
                db.add(cert)
            cert.endpoint_id = endpoint.id
            cert.is_active = True
            db.flush()
            certificate_payload = {
                "id": str(cert.id),
                "subject_cn": cert.subject_cn,
                "issuer_cn": cert.issuer_cn,
                "pubkey_algo": cert.pubkey_algo,
                "key_bits": cert.key_bits,
                "sig_algo": cert.sig_algo,
                "not_after": iso(cert.not_after),
                "unsupported_by_crypto_lib": cert.unsupported_by_crypto_lib,
                "sha256": cert.sha256,
            }
        except Exception as exc:  # noqa: BLE001 - fixture 异常时只记日志，扫描元数据仍落库
            parsed_error = f"{type(exc).__name__}: {exc}"
            logger.warning("scan parse failed endpoint=%s error=%s", endpoint.hostname, exc)

    endpoint.tls_versions = scan.tls_versions
    endpoint.cipher_suites = scan.cipher_suites
    endpoint.risk_level = scan.risk_level
    endpoint.last_scanned_at = utcnow()
    endpoint.simulated = True
    db.flush()
    # 评估在独立 session 内重算全量链/评分，必须先提交本事务，否则它看不到新证书
    db.commit()

    outcome = assessment_service.run_assessment(run_id=None)
    db.refresh(endpoint)
    chain = (
        db.query(ChainRecord).filter(ChainRecord.endpoint_id == endpoint.id).one_or_none()
    )
    assessment = (
        db.query(AlgorithmAssessment)
        .filter(AlgorithmAssessment.certificate_id == certificate_payload["id"])
        .one_or_none()
        if certificate_payload
        else None
    )
    cert_row = (
        db.get(CertificateAsset, certificate_payload["id"]) if certificate_payload else None
    )
    return {
        "endpoint": serialize_endpoint_row(endpoint),
        "scan": {
            "simulated": True,
            "cert_fixture": scan.cert_fixture,
            "tls_versions": scan.tls_versions,
            "cipher_suites": scan.cipher_suites,
            "risk_level": scan.risk_level,
            "notes": scan.notes,
            "parsed_error": parsed_error,
        },
        "certificate": certificate_payload,
        "certificate_row": (
            serialize_cert_row(cert_row, endpoint, assessment, chain) if cert_row else None
        ),
        "chain": serialize_chain(db, chain) if chain else None,
        "assessment_summary": outcome.to_dict(),
    }


def serialize_endpoint_row(endpoint: TlsEndpoint) -> dict[str, Any]:
    return {
        "id": str(endpoint.id),
        "hostname": endpoint.hostname,
        "port": endpoint.port,
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


def expiry_bucket_counts(db: Session, *, user: User) -> dict[str, int]:
    from src.utils.timeutil import expiry_bucket

    scope = dept_scope(user)
    query = db.query(CertificateAsset, TlsEndpoint).outerjoin(
        TlsEndpoint, TlsEndpoint.id == CertificateAsset.endpoint_id
    )
    if scope:
        query = query.filter(TlsEndpoint.dept == scope)
    counts = {b.value: 0 for b in ExpiryBucket}
    for cert, _endpoint in query.all():
        bucket = expiry_bucket(cert.not_after)
        counts[bucket] = counts.get(bucket, 0) + 1
    return counts


# ==========================================================================
# 受控模拟扫描：发现环节是模拟的（sha256 确定性挑本地 fixture），
# 证书解析 / 链校验 / 评分全部真实（见 README「诚实边界」）。
# ==========================================================================

SCAN_FIXTURES_DIR = Path(settings.cert_fixtures_dir)

# 可被"扫描"到的叶证书样本池（都不含私钥；CA 证书不作为端点证书下发）
SCAN_POOL: tuple[str, ...] = (
    "leaf_ok.pem",
    "leaf_rsa1024.pem",
    "leaf_sha1.pem",
    "leaf_ecdsa_p256.pem",
    "leaf_selfsigned.pem",
    "leaf_expiring30.pem",
    "leaf_sm2.pem",
)

TLS_LIBRARY: tuple[tuple[str, ...], ...] = (
    ("TLS1.3", "TLS1.2"),
    ("TLS1.2",),
    ("TLS1.2", "TLS1.1", "TLS1.0"),
    ("TLS1.2", "TLS1.1"),
)

CIPHER_LIBRARY: tuple[tuple[str, ...], ...] = (
    ("TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384"),
    ("ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"),
    ("ECDHE-RSA-AES128-SHA", "AES128-SHA"),
    ("ECDHE-SM2-SM4-CBC-SM3", "ECC-SM2-SM4-CBC-SM3"),
)


@dataclass
class SimulatedScan:
    hostname: str
    port: int
    tls_versions: list[str] = field(default_factory=list)
    cipher_suites: list[str] = field(default_factory=list)
    risk_level: str = EndpointRisk.MEDIUM.value
    cert_fixture: str = ""
    pem: str = ""
    simulated: bool = True
    notes: list[str] = field(default_factory=list)


def _digest(hostname: str, port: int) -> bytes:
    return hashlib.sha256(f"{hostname.lower()}:{port}".encode("utf-8")).digest()


def _pick(seq, digest: bytes, offset: int):
    return seq[digest[offset] % len(seq)]


def simulate_scan(hostname: str, port: int = 443, internet_facing: bool = False) -> SimulatedScan:
    """确定性模拟扫描：同一 hostname+port 永远得到同一份结果（可复现）。"""
    digest = _digest(hostname, port)
    fixture = _pick(SCAN_POOL, digest, 0)
    tls_versions = list(_pick(TLS_LIBRARY, digest, 1))
    cipher_suites = list(_pick(CIPHER_LIBRARY, digest, 2))
    pem_path = SCAN_FIXTURES_DIR / fixture
    pem = pem_path.read_text(encoding="utf-8") if pem_path.exists() else ""

    scan = SimulatedScan(
        hostname=hostname,
        port=port,
        tls_versions=tls_versions,
        cipher_suites=cipher_suites,
        cert_fixture=fixture,
        pem=pem,
        risk_level=_risk_level(fixture, tls_versions),
    )
    if not pem:
        scan.notes.append(f"fixtures 缺失 {fixture}，本次扫描只有握手元数据（无证书样本）")
    if not internet_facing:
        scan.notes.append("内网端点：按受控口径只做本地样本解析，不发起真实连接")
    return scan


def _risk_level(fixture: str, tls_versions: list[str]) -> str:
    if fixture in ("leaf_sha1.pem", "leaf_rsa1024.pem"):
        return EndpointRisk.CRITICAL.value
    if fixture in ("leaf_selfsigned.pem", "leaf_sm2.pem"):
        return EndpointRisk.HIGH.value
    if fixture == "leaf_expiring30.pem" or "TLS1.1" in tls_versions or "TLS1.0" in tls_versions:
        return EndpointRisk.HIGH.value
    if "TLS1.3" in tls_versions and fixture == "leaf_ok.pem":
        return EndpointRisk.LOW.value
    return EndpointRisk.MEDIUM.value
