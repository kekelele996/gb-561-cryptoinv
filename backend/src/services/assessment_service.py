"""评估编排：真解析 -> 真建链 -> 真评分 -> 落库（AlgorithmAssessment / ChainRecord）。

一次评估批次会：
  1. 从库里取全部证书 PEM，重新用 `cryptography` 解析（不缓存解析结果，保证"每次真解析"）；
  2. 按端点构链（叶子 + 端点证书 + 全局 CA 池），并做 hostname 匹配；
  3. 用 services.strength 给每张证书打分、打标签、出合规结论；
  4. 为每个「有生效叶证书」的端点写一条 ChainRecord；
  5. 汇总桶计数写 Redis 进度键，worker / API 都能查。
"""

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from sqlalchemy.orm import Session

from src.config.database import session_scope
from src.constants.enums import (
    ChainValidation,
    Compliance,
    ExpiryBucket,
    MigrationPriority,
    RiskTag,
)
from src.models.algorithm_assessment import AlgorithmAssessment
from src.models.certificate_asset import CertificateAsset
from src.models.chain_record import ChainRecord
from src.models.tls_endpoint import TlsEndpoint
from src.models.user import User
from src.services.certificate_service import algo_label, dept_scope
from src.services import strength as strength_algo
from src.services.x509_audit import ChainResult, apply_name_match, build_chain, parse_pem, ParsedCertificate
from src.utils.logger import get_logger
from src.utils.redis_client import get_redis
from src.utils.timeutil import utcnow

logger = get_logger("cryptoinv.assessment")

PROGRESS_KEY = "cryptoinv:assess:progress:{run_id}"
SUMMARY_KEY = "cryptoinv:assess:summary:{run_id}"
WORKER_HEARTBEAT_KEY = "cryptoinv:worker:heartbeat"


@dataclass
class AssessmentOutcome:
    cert_total: int = 0
    chain_total: int = 0
    chain_valid: int = 0
    chain_expired: int = 0
    chain_name_mismatch: int = 0
    chain_incomplete: int = 0
    compliant: int = 0
    non_compliant: int = 0
    grace: int = 0
    unknown_algo: int = 0
    avg_score: float = 0.0
    buckets: dict[str, int] = field(default_factory=dict)
    priority_hint: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cert_total": self.cert_total,
            "chain_total": self.chain_total,
            "chain_valid": self.chain_valid,
            "chain_expired": self.chain_expired,
            "chain_name_mismatch": self.chain_name_mismatch,
            "chain_incomplete": self.chain_incomplete,
            "compliant": self.compliant,
            "non_compliant": self.non_compliant,
            "grace": self.grace,
            "unknown_algo": self.unknown_algo,
            "avg_score": self.avg_score,
            "buckets": self.buckets,
            "priority_hint": self.priority_hint,
        }


def _progress(run_id: str | None, phase: str, detail: dict[str, Any] | None = None) -> None:
    if not run_id:
        return
    try:
        payload = {"phase": phase, "at": utcnow().isoformat(), "detail": detail or {}}
        get_redis().setex(
            PROGRESS_KEY.format(run_id=run_id), 3600, json.dumps(payload, ensure_ascii=False)
        )
    except Exception as exc:  # noqa: BLE001 - Redis 抖动不能影响评估
        logger.warning("progress write failed run=%s err=%s", run_id, exc)


def chain_index(db: Session, parsed: dict[str, ParsedCertificate]) -> dict[str, ChainResult]:
    """为每张证书算出它的链结论（端点证书用端点池，CA 证书用 CA 池）。"""
    certs: list[CertificateAsset] = db.query(CertificateAsset).all()
    endpoints: dict[str, TlsEndpoint] = {str(e.id): e for e in db.query(TlsEndpoint).all()}

    ca_pool = [(str(c.id), parsed[str(c.id)]) for c in certs if c.is_ca and str(c.id) in parsed]
    by_endpoint: dict[str, list[CertificateAsset]] = {}
    for cert in certs:
        if cert.endpoint_id is not None:
            by_endpoint.setdefault(str(cert.endpoint_id), []).append(cert)

    results: dict[str, ChainResult] = {}
    for cert in certs:
        cert_id = str(cert.id)
        leaf = parsed.get(cert_id)
        if leaf is None:
            continue
        if cert.is_ca:
            pool = [item for item in ca_pool if item[0] != cert_id]
            results[cert_id] = build_chain(cert_id, leaf, pool)
            continue
        key = str(cert.endpoint_id) if cert.endpoint_id is not None else ""
        siblings = [
            (str(c.id), parsed[str(c.id)])
            for c in by_endpoint.get(key, [])
            if str(c.id) != cert_id and str(c.id) in parsed
        ]
        result = build_chain(cert_id, leaf, siblings + ca_pool)
        endpoint = endpoints.get(key)
        if endpoint is not None:
            apply_name_match(result, leaf, endpoint.hostname)
        results[cert_id] = result
    return results


def _upsert_assessment(db: Session, cert: CertificateAsset, result: strength_algo.StrengthResult,
                       existing: dict[str, AlgorithmAssessment]) -> AlgorithmAssessment:
    row = existing.get(str(cert.id))
    if row is None:
        row = AlgorithmAssessment(certificate_id=cert.id)
        db.add(row)
        existing[str(cert.id)] = row
    row.strength_score = result.strength_score
    row.risk_tags = result.risk_tags
    row.compliance = result.compliance
    row.key_strength = result.key_strength
    row.sig_strength = result.sig_strength
    row.validity_strength = result.validity_strength
    row.chain_trust = result.chain_trust
    row.agility = result.agility
    row.expiry_bucket = result.expiry_bucket
    row.days_left = result.days_left
    row.assessed_at = utcnow()
    return row


def run_assessment(
    *,
    run_id: str | None = None,
    progress_cb: Callable[[str, dict[str, Any]], None] | None = None,
) -> AssessmentOutcome:
    """执行一次全量评估并落库（幂等：按 certificate_id 更新，不新增重复行）。"""
    summary = AssessmentOutcome()
    _progress(run_id, "running", {"step": "load"})
    if progress_cb:
        progress_cb("load", {})

    with session_scope() as db:
        certs: list[CertificateAsset] = db.query(CertificateAsset).all()
        endpoints = {str(e.id): e for e in db.query(TlsEndpoint).all()}
        parsed: dict[str, ParsedCertificate] = {}
        for cert in certs:
            try:
                parsed[str(cert.id)] = parse_pem(cert.pem)
            except Exception as exc:  # noqa: BLE001 - 解析失败的证书跳过并记日志
                logger.warning("skip cert %s parse failed: %s", cert.cert_key, exc)

        _progress(run_id, "running", {"step": "chain", "parsed": len(parsed)})
        if progress_cb:
            progress_cb("chain", {"parsed": len(parsed)})
        chains = chain_index(db, parsed)

        existing = {str(row.certificate_id): row for row in db.query(AlgorithmAssessment).all()}
        scores: list[float] = []
        bucket_counts = {b.value: 0 for b in ExpiryBucket}
        priority_hint = {p.value: 0 for p in MigrationPriority}

        for cert in certs:
            cert_id = str(cert.id)
            chain = chains.get(cert_id)
            if chain is None:
                continue
            endpoint = endpoints.get(str(cert.endpoint_id)) if cert.endpoint_id else None
            tls_versions = endpoint.tls_versions if endpoint is not None else []
            scored = strength_algo.assess(
                pubkey_algo=cert.pubkey_algo,
                key_bits=cert.key_bits,
                sig_algo=cert.sig_algo,
                unsupported_by_crypto_lib=cert.unsupported_by_crypto_lib,
                not_after=cert.not_after,
                chain=chain,
                tls_versions=tls_versions,
            )
            scores.append(scored.strength_score)
            bucket_counts[scored.expiry_bucket] = bucket_counts.get(scored.expiry_bucket, 0) + 1
            _upsert_assessment(db, cert, scored, existing)

            if endpoint is not None:
                _, prio = strength_algo.priority_score_for(
                    strength_score=scored.strength_score,
                    days_left_value=scored.days_left,
                    bucket=scored.expiry_bucket,
                    dept_grade=endpoint.dept_grade,
                    internet_facing=endpoint.internet_facing,
                )
                priority_hint[prio] = priority_hint.get(prio, 0) + 1

        # ---- ChainRecord：每个有生效叶证书的端点一条 ----
        chains_by_endpoint: dict[str, tuple[CertificateAsset, ChainResult]] = {}
        for cert in certs:
            if cert.is_ca or cert.endpoint_id is None or not cert.is_active:
                continue
            chain = chains.get(str(cert.id))
            if chain is None:
                continue
            key = str(cert.endpoint_id)
            current = chains_by_endpoint.get(key)
            if current is None or cert.not_before > current[0].not_before:
                chains_by_endpoint[key] = (cert, chain)

        existing_chains = {str(row.endpoint_id): row for row in db.query(ChainRecord).all()}
        validation_counts = {v.value: 0 for v in ChainValidation}
        for endpoint_key, (cert, chain) in chains_by_endpoint.items():
            row = existing_chains.get(endpoint_key)
            if row is None:
                row = ChainRecord(endpoint_id=cert.endpoint_id)
                db.add(row)
                existing_chains[endpoint_key] = row
            row.cert_path = chain.cert_path
            row.chain_length = chain.chain_length
            row.validation = chain.validation
            row.error_detail = chain.error_detail
            row.validated_at = utcnow()
            validation_counts[chain.validation] = validation_counts.get(chain.validation, 0) + 1

        db.flush()
        summary.cert_total = len(parsed)
        summary.chain_total = len(chains_by_endpoint)
        summary.chain_valid = validation_counts[ChainValidation.IS_VALID.value]
        summary.chain_expired = validation_counts[ChainValidation.EXPIRED.value]
        summary.chain_name_mismatch = validation_counts[ChainValidation.NAME_MISMATCH.value]
        summary.chain_incomplete = validation_counts[ChainValidation.INCOMPLETE.value]
        summary.buckets = bucket_counts
        summary.priority_hint = priority_hint
        summary.avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0

        comp_rows = db.query(AlgorithmAssessment).all()
        summary.compliant = sum(1 for r in comp_rows if r.compliance == Compliance.COMPLIANT.value)
        summary.non_compliant = sum(
            1 for r in comp_rows if r.compliance == Compliance.NON_COMPLIANT.value
        )
        summary.grace = sum(1 for r in comp_rows if r.compliance == Compliance.GRACE.value)
        summary.unknown_algo = sum(
            1 for r in comp_rows if "unknown_algo" in (r.risk_tags or [])
        )

    _progress(run_id, "done", summary.to_dict())
    if run_id:
        try:
            get_redis().setex(
                SUMMARY_KEY.format(run_id=run_id),
                3600,
                json.dumps(summary.to_dict(), ensure_ascii=False),
            )
        except Exception:  # noqa: BLE001
            pass
    logger.info(
        "assessment done certs=%s chains=%s valid=%s expired=%s mismatch=%s incomplete=%s avg=%s",
        summary.cert_total,
        summary.chain_total,
        summary.chain_valid,
        summary.chain_expired,
        summary.chain_name_mismatch,
        summary.chain_incomplete,
        summary.avg_score,
    )
    return summary


def read_progress(run_id: str) -> dict[str, Any]:
    try:
        raw = get_redis().get(PROGRESS_KEY.format(run_id=run_id))
    except Exception:  # noqa: BLE001
        raw = None
    if not raw:
        return {"phase": "unknown", "detail": {}, "run_id": run_id}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = {"phase": "unknown", "detail": {}}
    payload["run_id"] = run_id
    return payload


def worker_alive() -> bool:
    """Redis 心跳判断 worker 是否在线；不在线时 API 走同步兜底。"""
    try:
        value = get_redis().get(WORKER_HEARTBEAT_KEY)
        if not value:
            return False
        return (time.time() - float(value)) < 90
    except Exception:  # noqa: BLE001
        return False


# ==========================================================================
# 算法风险矩阵聚合（algo × dept）：全部取自 AlgorithmAssessment / CertificateAsset
# 真实字段，前端只渲染，不做任何本地计算。
# ==========================================================================

WEAK_TAGS = (RiskTag.WEAK_KEY.value, RiskTag.SHA1.value)

ALGO_ORDER = ("RSA-2048+", "RSA-SHA1", "RSA-1024", "ECDSA-P256", "ECDSA-P384", "SM2-SM3", "UNKNOWN")


def _empty_cell() -> dict[str, Any]:
    return {"count": 0, "score_sum": 0.0, "non_compliant": 0, "weak": 0, "expired": 0}


def build_matrix(db: Session, *, user: User, dept: str | None = None, metric: str = "avg_score") -> dict[str, Any]:
    scope = dept_scope(user)
    query = (
        db.query(CertificateAsset, TlsEndpoint, AlgorithmAssessment)
        .join(TlsEndpoint, TlsEndpoint.id == CertificateAsset.endpoint_id)
        .outerjoin(AlgorithmAssessment, AlgorithmAssessment.certificate_id == CertificateAsset.id)
    )
    if scope:
        query = query.filter(TlsEndpoint.dept == scope)
    elif dept:
        query = query.filter(TlsEndpoint.dept == dept)

    rows = query.all()
    depts = sorted({endpoint.dept for _cert, endpoint, _a in rows})
    cells: dict[tuple[str, str], dict[str, Any]] = {}
    for cert, endpoint, assessment in rows:
        label = algo_label(cert.pubkey_algo, cert.key_bits, cert.sig_algo, cert.unsupported_by_crypto_lib)
        key = (label, endpoint.dept)
        cell = cells.setdefault(key, _empty_cell())
        cell["count"] += 1
        if assessment is not None:
            cell["score_sum"] += assessment.strength_score
            if assessment.compliance == Compliance.NON_COMPLIANT.value:
                cell["non_compliant"] += 1
            if set(assessment.risk_tags or []) & set(WEAK_TAGS):
                cell["weak"] += 1
            if assessment.expiry_bucket == "expired":
                cell["expired"] += 1
        else:
            cell["score_sum"] += 0.0

    algos = [a for a in ALGO_ORDER if any(label == a for label, _ in cells)] + sorted(
        {label for label, _ in cells} - set(ALGO_ORDER)
    )
    payload_cells: list[dict[str, Any]] = []
    for label in algos:
        for dept_name in depts:
            cell = cells.get((label, dept_name))
            if cell is None:
                payload_cells.append(
                    {"algo": label, "dept": dept_name, "count": 0, "avg_score": None,
                     "non_compliant": 0, "weak": 0, "expired": 0}
                )
                continue
            payload_cells.append(
                {
                    "algo": label,
                    "dept": dept_name,
                    "count": cell["count"],
                    "avg_score": round(cell["score_sum"] / cell["count"], 2) if cell["count"] else None,
                    "non_compliant": cell["non_compliant"],
                    "weak": cell["weak"],
                    "expired": cell["expired"],
                }
            )

    dept_stats: list[dict[str, Any]] = []
    for dept_name in depts:
        own = [c for c in payload_cells if c["dept"] == dept_name and c["count"]]
        total = sum(c["count"] for c in own)
        avg = (
            round(sum(c["avg_score"] * c["count"] for c in own if c["avg_score"] is not None) / total, 2)
            if total
            else 0.0
        )
        dept_stats.append(
            {
                "dept": dept_name,
                "count": total,
                "avg_score": avg,
                "non_compliant": sum(c["non_compliant"] for c in own),
                "weak": sum(c["weak"] for c in own),
                "expired": sum(c["expired"] for c in own),
            }
        )
    dept_stats.sort(key=lambda item: item["avg_score"])

    algo_stats = []
    for label in algos:
        own = [c for c in payload_cells if c["algo"] == label and c["count"]]
        total = sum(c["count"] for c in own)
        avg = (
            round(sum(c["avg_score"] * c["count"] for c in own if c["avg_score"] is not None) / total, 2)
            if total
            else 0.0
        )
        algo_stats.append(
            {
                "algo": label,
                "count": total,
                "avg_score": avg,
                "non_compliant": sum(c["non_compliant"] for c in own),
                "weak": sum(c["weak"] for c in own),
            }
        )

    return {
        "algos": algos,
        "depts": depts,
        "cells": payload_cells,
        "dept_stats": dept_stats,
        "algo_stats": algo_stats,
        "metric": metric,
        "total_certificates": sum(c["count"] for c in payload_cells),
    }
