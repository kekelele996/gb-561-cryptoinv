"""评估 controller：发起批次（worker 异步 / 同步兜底）、查进度、查汇总。"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from src.models.user import User
from src.services import assessment_service, audit_service
from src.tasks_dispatcher import enqueue_assessment
from src.utils.logger import get_logger

logger = get_logger("cryptoinv.controller.assessment")


def run(request: Request, db: Session, user: User, mode: str = "auto") -> dict[str, Any]:
    run_id = uuid.uuid4().hex[:16]
    dispatched = False
    if mode != "inline" and assessment_service.worker_alive():
        dispatched = enqueue_assessment(run_id) is not None

    if dispatched:
        mode_used = "worker"
        result: dict[str, Any] = {"run_id": run_id, "mode": mode_used, "status": "queued"}
    else:
        mode_used = "inline"
        outcome = assessment_service.run_assessment(run_id=run_id)
        result = {
            "run_id": run_id,
            "mode": mode_used,
            "status": "done",
            "summary": outcome.to_dict(),
        }

    audit_service.record(
        db,
        action="assessment.run",
        entity_type="AlgorithmAssessment",
        entity_id=run_id,
        actor_id=str(user.id),
        payload={"mode": mode_used},
        ip=getattr(request.state, "client_ip", None),
        trace_id=getattr(request.state, "trace_id", None),
    )
    return result


def run_status(run_id: str) -> dict[str, Any]:
    return assessment_service.read_progress(run_id)


def summary(db: Session, user: User) -> dict[str, Any]:
    return {
        "buckets": _bucket_counts(db, user),
        "compliance": _compliance_counts(db),
        "risk_tags": _tag_counts(db),
        "avg_score": _avg_score(db),
        "cert_total": _cert_total(db),
    }


def _bucket_counts(db: Session, user: User) -> dict[str, int]:
    from src.services.endpoint_service import expiry_bucket_counts

    return expiry_bucket_counts(db, user=user)


def _compliance_rows(db: Session):
    from src.models.algorithm_assessment import AlgorithmAssessment

    return db.query(AlgorithmAssessment).all()


def _compliance_counts(db: Session) -> dict[str, int]:
    from src.constants.enums import Compliance

    counts = {c.value: 0 for c in Compliance}
    for row in _compliance_rows(db):
        counts[row.compliance] = counts.get(row.compliance, 0) + 1
    return counts


def _tag_counts(db: Session) -> dict[str, int]:
    from src.constants.enums import RiskTag

    counts = {t.value: 0 for t in RiskTag}
    for row in _compliance_rows(db):
        for tag in row.risk_tags or []:
            counts[tag] = counts.get(tag, 0) + 1
    return counts


def _avg_score(db: Session) -> float:
    rows = _compliance_rows(db)
    return round(sum(r.strength_score for r in rows) / len(rows), 2) if rows else 0.0


def _cert_total(db: Session) -> int:
    from src.models.algorithm_assessment import AlgorithmAssessment

    return db.query(AlgorithmAssessment).count()
