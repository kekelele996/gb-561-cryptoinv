"""迁移清单服务：生成/刷新、列表、状态流转、汇总、CSV 行。

优先级/窗口/目标算法全部由 `services.strength` 的真实评分推导：
  生成规则 = 对每张「有端点、非 CA」的证书重算 priority_score，
             补齐 P0/P1（紧急）缺失项；已有项只刷新分数/窗口，不覆盖用户改过的 status。
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from src.constants import error_codes as codes
from src.constants.enums import (
    MIGRATION_TRANSITIONS,
    MigrationPriority,
    MigrationStatus,
    RiskTag,
)
from src.constants.limits import DEFAULT_PAGE_SIZE
from src.models.algorithm_assessment import AlgorithmAssessment
from src.models.certificate_asset import CertificateAsset
from src.models.migration_item import MigrationItem
from src.models.tls_endpoint import TlsEndpoint
from src.models.user import User
from src.services import strength as strength_algo
from src.services.certificate_service import algo_label, clamp_page, dept_scope, paged
from src.utils.errors import AppError, not_found
from src.utils.logger import get_logger
from src.utils.timeutil import iso, utcnow

logger = get_logger("cryptoinv.migration")

AUTO_GENERATE_PRIORITIES = (MigrationPriority.P0.value, MigrationPriority.P1.value)


def _priority_payload(
    cert: CertificateAsset, assessment: AlgorithmAssessment, endpoint: TlsEndpoint
) -> dict[str, Any]:
    left = assessment.days_left
    bucket = assessment.expiry_bucket
    score, priority = strength_algo.priority_score_for(
        strength_score=assessment.strength_score,
        days_left_value=left,
        bucket=bucket,
        dept_grade=endpoint.dept_grade,
        internet_facing=endpoint.internet_facing,
    )
    window = strength_algo.batch_window_for(bucket, left)
    target = strength_algo.target_algo_for(cert.pubkey_algo, cert.sig_algo, assessment.risk_tags or [])
    return {
        "priority_score": score,
        "priority": priority,
        "batch_window": window,
        "target_algo": target,
        "rationale": (
            f"{algo_label(cert.pubkey_algo, cert.key_bits, cert.sig_algo, cert.unsupported_by_crypto_lib)}"
            f" 剩余 {left} 天；tags={','.join(assessment.risk_tags or []) or 'none'}；"
            f"dept_grade={endpoint.dept_grade} internet_facing={endpoint.internet_facing}"
        ),
    }


def candidate_rows(db: Session) -> list[tuple[CertificateAsset, AlgorithmAssessment, TlsEndpoint]]:
    """迁移候选：**仅当前生效的叶证书**；历史证书（is_active=False）只参与台账/矩阵，不进迁移清单。"""
    rows = (
        db.query(CertificateAsset, AlgorithmAssessment, TlsEndpoint)
        .join(TlsEndpoint, TlsEndpoint.id == CertificateAsset.endpoint_id)
        .join(AlgorithmAssessment, AlgorithmAssessment.certificate_id == CertificateAsset.id)
        .filter(CertificateAsset.is_ca.is_(False))
        .filter(CertificateAsset.is_active.is_(True))
        .all()
    )
    return list(rows)


def generate(db: Session, *, user: User) -> dict[str, Any]:
    """生成/刷新迁移清单（幂等：按 certificate_id upsert）。"""
    created = 0
    refreshed = 0
    by_priority = {p.value: 0 for p in MigrationPriority}
    existing = {str(item.certificate_id): item for item in db.query(MigrationItem).all()}
    manual: list[dict[str, str]] = []

    for cert, assessment, endpoint in candidate_rows(db):
        tags = assessment.risk_tags or []
        if RiskTag.UNKNOWN_ALGO.value in tags:
            # 无法识别的算法不参与优先级，进人工清单
            manual.append({"certificate_id": str(cert.id), "subject_cn": cert.subject_cn})
            continue
        payload = _priority_payload(cert, assessment, endpoint)
        by_priority[payload["priority"]] = by_priority.get(payload["priority"], 0) + 1
        item = existing.get(str(cert.id))
        if item is None:
            if payload["priority"] not in AUTO_GENERATE_PRIORITIES:
                continue
            item = MigrationItem(
                certificate_id=cert.id,
                target_algo=payload["target_algo"],
                priority=payload["priority"],
                priority_score=payload["priority_score"],
                batch_window=payload["batch_window"],
                status=MigrationStatus.TODO.value,
                rationale=payload["rationale"],
            )
            db.add(item)
            existing[str(cert.id)] = item
            created += 1
        else:
            item.target_algo = payload["target_algo"]
            item.priority = payload["priority"]
            item.priority_score = payload["priority_score"]
            item.batch_window = payload["batch_window"]
            item.rationale = payload["rationale"]
            refreshed += 1

    db.flush()
    return {
        "created": created,
        "refreshed": refreshed,
        "total": db.query(MigrationItem).count(),
        "computed_by_priority": by_priority,
        "manual_review": manual,
        "generated_at": iso(utcnow()),
    }


def create_item(
    db: Session, *, certificate_id: str, actor: User | None = None
) -> MigrationItem:
    """按单张证书补建迁移项（seed 用，走同一套真实优先级计算）。"""
    cert = db.get(CertificateAsset, certificate_id)
    if cert is None:
        raise not_found("CertificateAsset", certificate_id)
    assessment = (
        db.query(AlgorithmAssessment)
        .filter(AlgorithmAssessment.certificate_id == cert.id)
        .one_or_none()
    )
    if assessment is None:
        raise AppError(codes.NOT_FOUND, "证书尚未评估，不能生成迁移项", f"cert={certificate_id}")
    endpoint = db.get(TlsEndpoint, cert.endpoint_id) if cert.endpoint_id else None
    if endpoint is None:
        raise AppError(codes.NOT_FOUND, "证书未关联端点，不能生成迁移项", f"cert={certificate_id}")
    payload = _priority_payload(cert, assessment, endpoint)
    item = MigrationItem(
        certificate_id=cert.id,
        target_algo=payload["target_algo"],
        priority=payload["priority"],
        priority_score=payload["priority_score"],
        batch_window=payload["batch_window"],
        status=MigrationStatus.TODO.value,
        rationale=payload["rationale"],
    )
    db.add(item)
    db.flush()
    return item


def list_items(
    db: Session,
    *,
    user: User,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    priority: str | None = None,
    status: str | None = None,
    window: str | None = None,
    dept: str | None = None,
) -> dict[str, Any]:
    page, size = clamp_page(page, page_size)
    scope = dept_scope(user)
    query = (
        db.query(MigrationItem, CertificateAsset, TlsEndpoint, AlgorithmAssessment)
        .join(CertificateAsset, CertificateAsset.id == MigrationItem.certificate_id)
        .join(TlsEndpoint, TlsEndpoint.id == CertificateAsset.endpoint_id)
        .join(AlgorithmAssessment, AlgorithmAssessment.certificate_id == CertificateAsset.id)
    )
    if scope:
        query = query.filter(TlsEndpoint.dept == scope)
    elif dept:
        query = query.filter(TlsEndpoint.dept == dept)
    if priority:
        query = query.filter(MigrationItem.priority == priority)
    if status:
        query = query.filter(MigrationItem.status == status)
    if window:
        query = query.filter(MigrationItem.batch_window == window)

    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    rows = query.all()
    rows.sort(key=lambda row: (order.get(row[0].priority, 9), -row[0].priority_score))
    total = len(rows)
    start = (page - 1) * size
    items = [serialize_item(item, cert, endpoint, assessment) for item, cert, endpoint, assessment in rows[start : start + size]]
    return {
        **paged(items, total, page, size),
        "summary": summary(db, user=user, dept=dept),
    }


def serialize_item(
    item: MigrationItem,
    cert: CertificateAsset,
    endpoint: TlsEndpoint,
    assessment: AlgorithmAssessment,
) -> dict[str, Any]:
    return {
        "id": str(item.id),
        "certificate_id": str(cert.id),
        "subject_cn": cert.subject_cn,
        "serial": cert.serial,
        "algo_label": algo_label(cert.pubkey_algo, cert.key_bits, cert.sig_algo, cert.unsupported_by_crypto_lib),
        "sig_algo": cert.sig_algo,
        "key_bits": cert.key_bits,
        "hostname": endpoint.hostname,
        "dept": endpoint.dept,
        "system_name": endpoint.system_name,
        "internet_facing": endpoint.internet_facing,
        "dept_grade": endpoint.dept_grade,
        "target_algo": item.target_algo,
        "priority": item.priority,
        "priority_score": item.priority_score,
        "batch_window": item.batch_window,
        "status": item.status,
        "rationale": item.rationale,
        "strength_score": assessment.strength_score,
        "risk_tags": assessment.risk_tags,
        "days_left": assessment.days_left,
        "not_after": iso(cert.not_after),
        "planned_at": iso(item.planned_at),
        "done_at": iso(item.done_at),
        "allowed_transitions": list(MIGRATION_TRANSITIONS.get(item.status, ())),
    }


def summary(db: Session, *, user: User, dept: str | None = None) -> dict[str, Any]:
    scope = dept_scope(user) or dept
    query = (
        db.query(MigrationItem, TlsEndpoint)
        .join(CertificateAsset, CertificateAsset.id == MigrationItem.certificate_id)
        .join(TlsEndpoint, TlsEndpoint.id == CertificateAsset.endpoint_id)
    )
    if scope:
        query = query.filter(TlsEndpoint.dept == scope)
    rows = query.all()
    by_priority = {p.value: 0 for p in MigrationPriority}
    by_status = {s.value: 0 for s in MigrationStatus}
    by_window: dict[str, int] = {}
    for item, _endpoint in rows:
        by_priority[item.priority] = by_priority.get(item.priority, 0) + 1
        by_status[item.status] = by_status.get(item.status, 0) + 1
        by_window[item.batch_window] = by_window.get(item.batch_window, 0) + 1
    return {
        "total": len(rows),
        "by_priority": by_priority,
        "by_status": by_status,
        "by_window": dict(sorted(by_window.items())),
    }


def transition(db: Session, *, item_id: str, to_status: str, user: User) -> dict[str, Any]:
    item = db.get(MigrationItem, item_id)
    if item is None:
        raise not_found("MigrationItem", item_id)
    cert = db.get(CertificateAsset, item.certificate_id)
    endpoint = db.get(TlsEndpoint, cert.endpoint_id) if cert and cert.endpoint_id else None
    scope = dept_scope(user)
    if scope and endpoint is not None and endpoint.dept != scope:
        raise AppError(codes.FORBIDDEN, "无权修改其它厅局的迁移项", f"dept={endpoint.dept}")
    allowed = MIGRATION_TRANSITIONS.get(item.status, ())
    if to_status not in allowed:
        raise AppError(
            codes.MIGRATION_TRANSITION_INVALID,
            None,
            f"{item.status} -> {to_status} 不在允许流转 {allowed}",
        )
    item.status = to_status
    if to_status == MigrationStatus.SCHEDULED.value and item.planned_at is None:
        item.planned_at = utcnow()
    if to_status == MigrationStatus.DONE.value:
        item.done_at = utcnow()
    db.flush()
    return {
        "id": str(item.id),
        "status": item.status,
        "planned_at": iso(item.planned_at),
        "done_at": iso(item.done_at),
        "allowed_transitions": list(MIGRATION_TRANSITIONS.get(item.status, ())),
    }


def export_rows(
    db: Session, *, user: User, dept: str | None = None, priority: str | None = None
) -> list[dict[str, Any]]:
    data = list_items(
        db, user=user, page=1, page_size=10000, priority=priority, dept=dept
    )
    columns = [
        "priority",
        "priority_score",
        "batch_window",
        "status",
        "target_algo",
        "algo_label",
        "hostname",
        "dept",
        "system_name",
        "internet_facing",
        "strength_score",
        "risk_tags",
        "days_left",
        "not_after",
        "subject_cn",
        "serial",
    ]
    rows: list[dict[str, Any]] = []
    for item in data["items"]:
        rows.append(
            {
                "priority": item["priority"],
                "priority_score": item["priority_score"],
                "batch_window": item["batch_window"],
                "status": item["status"],
                "target_algo": item["target_algo"],
                "algo_label": item["algo_label"],
                "hostname": item["hostname"],
                "dept": item["dept"],
                "system_name": item["system_name"],
                "internet_facing": "是" if item["internet_facing"] else "否",
                "strength_score": item["strength_score"],
                "risk_tags": ",".join(item["risk_tags"] or []),
                "days_left": item["days_left"],
                "not_after": item["not_after"],
                "subject_cn": item["subject_cn"],
                "serial": item["serial"],
            }
        )
    return rows
