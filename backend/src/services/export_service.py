"""导出服务：InventoryExport 记录 + CSV/JSON 内容生成。

导出审批口径：**只有 admin 能创建全量导出记录**（`exports:create`），
owner 尝试 -> 403；engineer 可以在迁移页导出 CSV（`migration:export`）。
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any

from sqlalchemy.orm import Session

from src.constants import error_codes as codes
from src.constants.enums import ExportFormat, ExportScope
from src.constants.limits import DEFAULT_PAGE_SIZE
from src.models.algorithm_assessment import AlgorithmAssessment
from src.models.certificate_asset import CertificateAsset
from src.models.inventory_export import InventoryExport
from src.models.tls_endpoint import TlsEndpoint
from src.models.user import User
from src.services.certificate_service import algo_label, clamp_page, dept_scope, paged
from src.services.migration_service import export_rows as migration_export_rows
from src.utils.errors import AppError, not_found
from src.utils.timeutil import iso, utcnow

INVENTORY_COLUMNS = [
    "cert_key",
    "subject_cn",
    "issuer_cn",
    "serial",
    "algo_label",
    "pubkey_algo",
    "key_bits",
    "sig_algo",
    "not_before",
    "not_after",
    "days_left",
    "expiry_bucket",
    "dept",
    "hostname",
    "internet_facing",
    "chain_validation",
    "strength_score",
    "compliance",
    "risk_tags",
]


def inventory_rows(db: Session, *, user: User, scope: str = ExportScope.ALL.value) -> list[dict[str, Any]]:
    user_scope = dept_scope(user)
    query = (
        db.query(CertificateAsset, TlsEndpoint, AlgorithmAssessment)
        .outerjoin(TlsEndpoint, TlsEndpoint.id == CertificateAsset.endpoint_id)
        .outerjoin(AlgorithmAssessment, AlgorithmAssessment.certificate_id == CertificateAsset.id)
    )
    if user_scope:
        query = query.filter(TlsEndpoint.dept == user_scope)
    rows = query.all()
    result: list[dict[str, Any]] = []
    for cert, endpoint, assessment in rows:
        result.append(
            {
                "cert_key": cert.cert_key,
                "subject_cn": cert.subject_cn,
                "issuer_cn": cert.issuer_cn,
                "serial": cert.serial,
                "algo_label": algo_label(
                    cert.pubkey_algo, cert.key_bits, cert.sig_algo, cert.unsupported_by_crypto_lib
                ),
                "pubkey_algo": cert.pubkey_algo,
                "key_bits": cert.key_bits or "",
                "sig_algo": cert.sig_algo,
                "not_before": iso(cert.not_before),
                "not_after": iso(cert.not_after),
                "days_left": assessment.days_left if assessment else "",
                "expiry_bucket": assessment.expiry_bucket if assessment else "",
                "dept": endpoint.dept if endpoint else "",
                "hostname": endpoint.hostname if endpoint else "",
                "internet_facing": ("是" if endpoint.internet_facing else "否") if endpoint else "",
                "chain_validation": assessment.chain_trust if assessment else "",
                "strength_score": assessment.strength_score if assessment else "",
                "compliance": assessment.compliance if assessment else "",
                "risk_tags": ",".join(assessment.risk_tags or []) if assessment else "",
                "source": cert.source,
                "sha256": cert.sha256,
            }
        )
    result.sort(key=lambda row: (str(row["dept"]), str(row["hostname"])))
    return result


def create_export(
    db: Session, *, user: User, name: str, scope: str = ExportScope.ALL.value,
    export_format: str = ExportFormat.CSV.value,
) -> dict[str, Any]:
    if scope not in {s.value for s in ExportScope}:
        raise AppError(codes.VALIDATION_ERROR, "导出范围不合法", f"scope={scope}")
    if export_format not in {f.value for f in ExportFormat}:
        raise AppError(codes.VALIDATION_ERROR, "导出格式不合法", f"format={export_format}")
    rows = inventory_rows(db, user=user, scope=scope)
    record = InventoryExport(
        name=name.strip()[:120] or f"密码资产盘点导出 {utcnow().date().isoformat()}",
        scope=scope,
        export_format=export_format,
        rows=len(rows),
        filters={"scope": scope, "format": export_format},
        generated_by=user.email,
        generated_at=utcnow(),
    )
    db.add(record)
    db.flush()
    return {"id": str(record.id), "rows": record.rows, "name": record.name, "format": export_format}


def list_exports(db: Session, *, user: User, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE) -> dict[str, Any]:
    page, size = clamp_page(page, page_size)
    query = db.query(InventoryExport)
    if dept_scope(user) is not None:
        # owner 只能看自己触发的导出（实际无权限创建，此处仍做最小暴露）
        query = query.filter(InventoryExport.generated_by == user.email)
    rows = query.order_by(InventoryExport.generated_at.desc()).all()
    total = len(rows)
    start = (page - 1) * size
    items = [
        {
            "id": str(row.id),
            "name": row.name,
            "scope": row.scope,
            "format": row.export_format,
            "rows": row.rows,
            "generated_by": row.generated_by,
            "generated_at": iso(row.generated_at),
        }
        for row in rows[start : start + size]
    ]
    return paged(items, total, page, size)


def to_csv(rows: list[dict[str, Any]], columns: list[str] | None = None) -> str:
    cols = columns or INVENTORY_COLUMNS
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=cols, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row.get(key, "") for key in cols})
    return buffer.getvalue()


def to_json(rows: list[dict[str, Any]]) -> str:
    return json.dumps(rows, ensure_ascii=False, indent=2)


def download(db: Session, *, export_id: str, user: User) -> tuple[str, str, str]:
    """返回 (filename, mimetype, content)。内容按当前数据重新生成（数据是最新的）。"""
    record = db.get(InventoryExport, export_id)
    if record is None:
        raise not_found("InventoryExport", export_id)
    suffix = record.export_format
    if suffix == ExportFormat.CSV.value:
        rows = inventory_rows(db, user=user, scope=record.scope)
        content = to_csv(rows)
        return f"cryptoinv-inventory-{record.generated_at.date().isoformat()}.csv", "text/csv", content
    rows = inventory_rows(db, user=user, scope=record.scope)
    content = to_json(rows)
    return f"cryptoinv-inventory-{record.generated_at.date().isoformat()}.json", "application/json", content


def migration_csv(db: Session, *, user: User, dept: str | None = None, priority: str | None = None) -> tuple[str, str]:
    rows = migration_export_rows(db, user=user, dept=dept, priority=priority)
    columns = list(rows[0].keys()) if rows else [
        "priority", "priority_score", "batch_window", "status", "target_algo"
    ]
    return "cryptoinv-migration-list.csv", to_csv(rows, columns)
