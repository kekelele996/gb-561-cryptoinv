"""共享枚举（组 1/2/3）：后端唯一真源，前端 `constants/enums.ts` 保持字面量一致。

README「枚举出现位置」列出全部引用点。数据库里存字符串值（不存 IntEnum 序号），
保证跨语言可直接比对。
"""
from __future__ import annotations

from enum import Enum


class MigrationPriority(str, Enum):
    """共享枚举 #1：迁移优先级 P0-P3。"""

    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class ChainValidation(str, Enum):
    """共享枚举 #2：链校验结论。"""

    IS_VALID = "is_valid"
    EXPIRED = "expired"
    NAME_MISMATCH = "name_mismatch"
    INCOMPLETE = "incomplete"


class RiskTag(str, Enum):
    """共享枚举 #3：算法风险标签。"""

    WEAK_KEY = "weak_key"
    SHA1 = "sha1"
    EXPIRED = "expired"
    SELF_SIGNED = "self_signed"
    QUANTUM_VULNERABLE = "quantum_vulnerable"
    UNKNOWN_ALGO = "unknown_algo"


class Compliance(str, Enum):
    """密评合规结论（口径见 README §算法 2）。"""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    GRACE = "grace"


class ExpiryBucket(str, Enum):
    """证书时效四档（台账看板 / 详情有效期条共用）。"""

    EXPIRED = "expired"
    SOON_30 = "soon_30"
    SOON_90 = "soon_90"
    NORMAL = "normal"


class MigrationStatus(str, Enum):
    """迁移项状态机：todo -> scheduled -> in_progress -> done，任意态 -> blocked。"""

    TODO = "todo"
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    BLOCKED = "blocked"


class MigrationTarget(str, Enum):
    """国密/强算法改造目标。"""

    SM2_SM3 = "SM2-SM3"
    ECDSA_P256 = "ECDSA-P256"
    RSA_2048_PLUS = "RSA-2048+"


class BatchWindow(str, Enum):
    """迁移批次窗口（由 urgency 推导）。"""

    W2026Q4 = "2026Q4"
    W2027Q1 = "2027Q1"
    W2027Q2 = "2027Q2"


class PubkeyAlgo(str, Enum):
    RSA = "RSA"
    ECDSA = "ECDSA"
    SM2 = "SM2"
    UNKNOWN = "UNKNOWN"


class CertSource(str, Enum):
    IMPORT = "import"
    SCAN = "scan"


class ExportFormat(str, Enum):
    CSV = "csv"
    JSON = "json"


class ExportScope(str, Enum):
    ALL = "all"
    DEPT = "dept"


class DeptGrade(str, Enum):
    """厅局等级：A 重点保障 / B 一般业务 / C 内部支撑（权重见 DEPT_GRADE_SCORE）。"""

    A = "A"
    B = "B"
    C = "C"


class EndpointRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# 硬性不合规标签：出现即 non_compliant（不论分数）
HARD_RISK_TAGS: tuple[str, ...] = (
    RiskTag.WEAK_KEY.value,
    RiskTag.SHA1.value,
    RiskTag.EXPIRED.value,
    RiskTag.UNKNOWN_ALGO.value,
)

# 优先级 -> 批次窗口的兜底顺序（只在 urgency 无法推导时使用）
PRIORITY_ORDER: tuple[str, ...] = (
    MigrationPriority.P0.value,
    MigrationPriority.P1.value,
    MigrationPriority.P2.value,
    MigrationPriority.P3.value,
)

MIGRATION_STATUS_ORDER: tuple[str, ...] = (
    MigrationStatus.TODO.value,
    MigrationStatus.SCHEDULED.value,
    MigrationStatus.IN_PROGRESS.value,
    MigrationStatus.DONE.value,
    MigrationStatus.BLOCKED.value,
)

# 状态机允许的流转（避免前端随便改态）
MIGRATION_TRANSITIONS: dict[str, tuple[str, ...]] = {
    MigrationStatus.TODO.value: (MigrationStatus.SCHEDULED.value, MigrationStatus.BLOCKED.value),
    MigrationStatus.SCHEDULED.value: (
        MigrationStatus.IN_PROGRESS.value,
        MigrationStatus.TODO.value,
        MigrationStatus.BLOCKED.value,
    ),
    MigrationStatus.IN_PROGRESS.value: (MigrationStatus.DONE.value, MigrationStatus.BLOCKED.value),
    MigrationStatus.DONE.value: (),
    MigrationStatus.BLOCKED.value: (MigrationStatus.TODO.value,),
}
