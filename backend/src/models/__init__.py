"""模型聚合：alembic 与 seed 都通过这里拿到完整 metadata。"""
from src.models.base import Base
from src.models.algorithm_assessment import AlgorithmAssessment
from src.models.audit_log import AuditLog
from src.models.certificate_asset import CertificateAsset
from src.models.chain_record import ChainRecord
from src.models.inventory_export import InventoryExport
from src.models.migration_item import MigrationItem
from src.models.tls_endpoint import TlsEndpoint
from src.models.user import User

__all__ = [
    "Base",
    "AlgorithmAssessment",
    "AuditLog",
    "CertificateAsset",
    "ChainRecord",
    "InventoryExport",
    "MigrationItem",
    "TlsEndpoint",
    "User",
]
