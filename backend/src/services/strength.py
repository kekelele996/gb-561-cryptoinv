"""核心算法 2：算法强度评分 + 风险标签 + 合规结论 + 迁移优先级。

strength_score = 0.35*key_strength + 0.25*sig_strength + 0.15*validity
               + 0.15*chain_trust + 0.10*agility        （0..100）

分量（README §算法 2 同步）：
  key_strength : RSA>=2048=1.0 / RSA-1024=0.35 / RSA<1024=0.1 /
                 ECDSA P-256/P-384=1.0 / SM2=1.0 / 未知=0.0
  sig_strength : SHA256+=1.0 / SHA1=0.2 / MD5=0.0 / SM3=1.0 / 未识别=0.0
  validity     : 正常=1.0 / <=90天=0.8 / <=30天=0.5 / 已过期=0.0
  chain_trust  : 完整已验证=1.0 / incomplete 或 name_mismatch=0.5 / self_signed=0.3
  agility      : 国密(SM2/SM3)=1.0 / 支持 TLS1.3 的现代算法=0.6 / 其余=0.4

风险标签：weak_key / sha1 / expired / self_signed / quantum_vulnerable / unknown_algo
  - quantum_vulnerable：RSA、ECDSA 全部标注（Shor 可破），SM2 不标
合规结论：硬性标签 -> non_compliant；score>=80 且非自签 -> compliant；
          score>=60 -> grace；其余 -> non_compliant

priority_score = 0.4*weakness + 0.3*urgency + 0.2*dept_risk + 0.1*exposure （0..100）
  weakness = 100 - strength_score
  urgency  : expired/<=30天=100 / <=90天=80 / <=180天=50 / <=365天=30 / 其余=10
  dept_risk: A=100 / B=70 / C=40        （计划口径 A=1.0 / B=0.7 / C=0.4 归一化到 100）
  exposure : internet_facing=100 / 内网=30
  -> P0>=70 / P1 50..70 / P2 30..50 / P3<30
批次窗口：urgency>=100 -> 2026Q4；>=80 -> 2027Q1；其余 -> 2027Q2
"""
from __future__ import annotations

from dataclasses import dataclass, field

from src.constants.enums import (
    BatchWindow,
    Compliance,
    DeptGrade,
    ExpiryBucket,
    MigrationPriority,
    MigrationTarget,
    PubkeyAlgo,
    RiskTag,
)
from src.services.x509_audit import ChainResult, chain_trust_score
from src.utils.oid_map import is_sha1_signature, is_sm_signature, signature_strength
from src.utils.timeutil import days_left

WEIGHTS = {"key": 0.35, "sig": 0.25, "validity": 0.15, "chain": 0.15, "agility": 0.10}

DEPT_RISK_SCORE = {DeptGrade.A.value: 100.0, DeptGrade.B.value: 70.0, DeptGrade.C.value: 40.0}

URGENCY_EXPIRED_OR_30 = 100.0
URGENCY_90 = 80.0
URGENCY_180 = 50.0
URGENCY_365 = 30.0
URGENCY_DEFAULT = 10.0

EXPOSURE_INTERNET = 100.0
EXPOSURE_INTERNAL = 30.0

COMPLIANT_MIN_SCORE = 80.0
GRACE_MIN_SCORE = 60.0

P0_MIN = 70.0
P1_MIN = 50.0
P2_MIN = 30.0


@dataclass
class StrengthResult:
    strength_score: float
    key_strength: float
    sig_strength: float
    validity_strength: float
    chain_trust: float
    agility: float
    risk_tags: list[str] = field(default_factory=list)
    compliance: str = Compliance.COMPLIANT.value
    expiry_bucket: str = ExpiryBucket.NORMAL.value
    days_left: int | None = None
    notes: list[str] = field(default_factory=list)


def key_strength(pubkey_algo: str, key_bits: int | None, unsupported: bool) -> float:
    algo = (pubkey_algo or "").upper()
    if unsupported or algo == PubkeyAlgo.UNKNOWN.value:
        return 0.0
    if algo == PubkeyAlgo.SM2.value:
        return 1.0
    if algo == PubkeyAlgo.ECDSA.value:
        return 1.0 if (key_bits or 0) >= 256 else 0.6
    if algo == PubkeyAlgo.RSA.value:
        bits = key_bits or 0
        if bits >= 2048:
            return 1.0
        if bits >= 1024:
            return 0.35
        return 0.1
    return 0.0


def validity_strength(bucket: str) -> float:
    return {
        ExpiryBucket.NORMAL.value: 1.0,
        ExpiryBucket.SOON_90.value: 0.8,
        ExpiryBucket.SOON_30.value: 0.5,
        ExpiryBucket.EXPIRED.value: 0.0,
    }.get(bucket, 0.5)


def agility_score(pubkey_algo: str, sig_algo: str, tls_versions: list[str] | None) -> float:
    if pubkey_algo == PubkeyAlgo.SM2.value or is_sm_signature(sig_algo):
        return 1.0
    versions = tls_versions or []
    if any(str(v).upper().replace(" ", "").replace("V", "").replace("_", ".").startswith("1.3") for v in versions):
        return 0.6
    return 0.4


def risk_tags(
    pubkey_algo: str,
    key_bits: int | None,
    sig_algo: str,
    bucket: str,
    self_signed: bool,
    unsupported: bool,
) -> list[str]:
    tags: list[str] = []
    algo = (pubkey_algo or "").upper()
    if unsupported or algo == PubkeyAlgo.UNKNOWN.value:
        tags.append(RiskTag.UNKNOWN_ALGO.value)
    if algo == PubkeyAlgo.RSA.value and (key_bits or 0) < 2048:
        tags.append(RiskTag.WEAK_KEY.value)
    if is_sha1_signature(sig_algo):
        tags.append(RiskTag.SHA1.value)
    if bucket == ExpiryBucket.EXPIRED.value:
        tags.append(RiskTag.EXPIRED.value)
    if self_signed:
        tags.append(RiskTag.SELF_SIGNED.value)
    # RSA / ECDSA 都标量子脆弱；SM2 不标
    if algo in (PubkeyAlgo.RSA.value, PubkeyAlgo.ECDSA.value):
        tags.append(RiskTag.QUANTUM_VULNERABLE.value)
    return tags


def compliance_for(score: float, tags: list[str]) -> str:
    hard = {RiskTag.WEAK_KEY.value, RiskTag.SHA1.value, RiskTag.EXPIRED.value, RiskTag.UNKNOWN_ALGO.value}
    if hard.intersection(tags):
        return Compliance.NON_COMPLIANT.value
    if score >= COMPLIANT_MIN_SCORE and RiskTag.SELF_SIGNED.value not in tags:
        return Compliance.COMPLIANT.value
    if score >= GRACE_MIN_SCORE:
        return Compliance.GRACE.value
    return Compliance.NON_COMPLIANT.value


def assess(
    *,
    pubkey_algo: str,
    key_bits: int | None,
    sig_algo: str,
    unsupported_by_crypto_lib: bool,
    not_after,
    chain: ChainResult,
    tls_versions: list[str] | None,
    now=None,
) -> StrengthResult:
    """纯函数评分：输入全为算法 1/扫描侧的真实解析结果。"""
    from src.utils.timeutil import expiry_bucket

    bucket = expiry_bucket(not_after, now)
    left = days_left(not_after, now)
    self_signed = bool(chain.self_signed)

    key_s = key_strength(pubkey_algo, key_bits, unsupported_by_crypto_lib)
    sig_s = signature_strength(sig_algo)
    val_s = validity_strength(bucket)
    chain_s = chain_trust_score(chain)
    if chain.validation in ("incomplete", "name_mismatch"):
        chain_s = 0.5
    agi_s = agility_score(pubkey_algo, sig_algo, tls_versions)

    raw = (
        WEIGHTS["key"] * key_s
        + WEIGHTS["sig"] * sig_s
        + WEIGHTS["validity"] * val_s
        + WEIGHTS["chain"] * chain_s
        + WEIGHTS["agility"] * agi_s
    )
    score = round(raw * 100, 2)
    tags = risk_tags(
        pubkey_algo, key_bits, sig_algo, bucket, self_signed, unsupported_by_crypto_lib
    )
    result = StrengthResult(
        strength_score=score,
        key_strength=round(key_s, 4),
        sig_strength=round(sig_s, 4),
        validity_strength=round(val_s, 4),
        chain_trust=round(chain_s, 4),
        agility=round(agi_s, 4),
        risk_tags=tags,
        compliance=compliance_for(score, tags),
        expiry_bucket=bucket,
        days_left=left,
    )
    if unsupported_by_crypto_lib:
        result.notes.append("公钥曲线不被 cryptography/OpenSSL 支持，按 unknown_algo 处理")
    return result


def urgency_score(left: int | None, bucket: str) -> float:
    if bucket == ExpiryBucket.EXPIRED.value or left is None:
        return URGENCY_EXPIRED_OR_30 if bucket == ExpiryBucket.EXPIRED.value else URGENCY_365
    if left <= 30:
        return URGENCY_EXPIRED_OR_30
    if left <= 90:
        return URGENCY_90
    if left <= 180:
        return URGENCY_180
    if left <= 365:
        return URGENCY_365
    return URGENCY_DEFAULT


def priority_score_for(
    *,
    strength_score: float,
    days_left_value: int | None,
    bucket: str,
    dept_grade: str,
    internet_facing: bool,
) -> tuple[float, str]:
    """返回 (priority_score, priority)。未知算法（score=0 且 unknown_algo）不参与优先级。"""
    weakness = max(0.0, 100.0 - strength_score)
    urgency = urgency_score(days_left_value, bucket)
    dept_risk = DEPT_RISK_SCORE.get((dept_grade or "B").upper(), DEPT_RISK_SCORE["B"])
    exposure = EXPOSURE_INTERNET if internet_facing else EXPOSURE_INTERNAL
    score = round(0.4 * weakness + 0.3 * urgency + 0.2 * dept_risk + 0.1 * exposure, 2)
    if score >= P0_MIN:
        return score, MigrationPriority.P0.value
    if score >= P1_MIN:
        return score, MigrationPriority.P1.value
    if score >= P2_MIN:
        return score, MigrationPriority.P2.value
    return score, MigrationPriority.P3.value


def batch_window_for(bucket: str, days_left_value: int | None) -> str:
    urgency = urgency_score(days_left_value, bucket)
    if urgency >= URGENCY_EXPIRED_OR_30:
        return BatchWindow.W2026Q4.value
    if urgency >= URGENCY_90:
        return BatchWindow.W2027Q1.value
    return BatchWindow.W2027Q2.value


def target_algo_for(pubkey_algo: str, sig_algo: str, tags: list[str]) -> str:
    """迁移目标算法建议：国密优先，其次 ECDSA-P256，最后 RSA-2048+。"""
    if PubkeyAlgo.UNKNOWN.value in tags:
        return MigrationTarget.SM2_SM3.value
    if pubkey_algo == PubkeyAlgo.RSA.value and (RiskTag.WEAK_KEY.value in tags or RiskTag.SHA1.value in tags):
        return MigrationTarget.SM2_SM3.value
    if RiskTag.QUANTUM_VULNERABLE.value in tags and pubkey_algo != PubkeyAlgo.UNKNOWN.value:
        return MigrationTarget.ECDSA_P256.value
    return MigrationTarget.RSA_2048_PLUS.value


def explain(result: StrengthResult, priority: str, score: float, window: str) -> str:
    """给详情页/导出用的一句可读理由（全部由真实分量拼出）。"""
    parts = [
        f"key={result.key_strength}",
        f"sig={result.sig_strength}",
        f"validity={result.validity_strength}",
        f"chain={result.chain_trust}",
        f"agility={result.agility}",
    ]
    return (
        f"strength={result.strength_score}（{', '.join(parts)}）；"
        f"tags={','.join(result.risk_tags) or 'none'}；"
        f"priority={priority}({score}) 窗口={window}"
    )
