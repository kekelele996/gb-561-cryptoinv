"""签名算法 OID -> 名称映射，以及公钥算法判定。

`cryptography` 的 `signature_algorithm_oid.dotted_string` 是稳定输入，
名称映射在这里集中维护，避免各地硬编码 OID。
"""
from __future__ import annotations

RSA_SHA1 = "1.2.840.113549.1.1.5"
RSA_SHA256 = "1.2.840.113549.1.1.11"
RSA_SHA384 = "1.2.840.113549.1.1.12"
RSA_SHA512 = "1.2.840.113549.1.1.13"
RSA_MD5 = "1.2.840.113549.1.1.4"
ECDSA_SHA256 = "1.2.840.10045.4.3.2"
ECDSA_SHA384 = "1.2.840.10045.4.3.3"
ECDSA_SHA512 = "1.2.840.10045.4.3.4"
SM2_SM3 = "1.2.156.10197.1.501"

SIGNATURE_ALGORITHMS: dict[str, str] = {
    RSA_MD5: "RSA-MD5",
    RSA_SHA1: "RSA-SHA1",
    RSA_SHA256: "RSA-SHA256",
    RSA_SHA384: "RSA-SHA384",
    RSA_SHA512: "RSA-SHA512",
    ECDSA_SHA256: "ECDSA-SHA256",
    ECDSA_SHA384: "ECDSA-SHA384",
    ECDSA_SHA512: "ECDSA-SHA512",
    SM2_SM3: "SM2-SM3",
}

# 签名强度：SHA256 及以上 = 1.0 / SHA1 = 0.2 / MD5 = 0.0 / SM3 = 1.0
SIGNATURE_STRENGTH: dict[str, float] = {
    "RSA-MD5": 0.0,
    "RSA-SHA1": 0.2,
    "RSA-SHA256": 1.0,
    "RSA-SHA384": 1.0,
    "RSA-SHA512": 1.0,
    "ECDSA-SHA256": 1.0,
    "ECDSA-SHA384": 1.0,
    "ECDSA-SHA512": 1.0,
    "SM2-SM3": 1.0,
}

# 国密签名算法（agility 判定用）
SM_SIGNATURES = ("SM2-SM3",)
# 弱签名算法（sha1 风险标签用）
SHA1_SIGNATURES = ("RSA-SHA1",)


def map_signature_oid(dotted: str) -> tuple[str, bool]:
    """返回 (名称, 是否被本系统识别)。未识别 OID 原样返回并标记 False。"""
    mapped = SIGNATURE_ALGORITHMS.get(dotted)
    if mapped is None:
        return dotted, False
    return mapped, True


def signature_strength(sig_algo: str) -> float:
    return SIGNATURE_STRENGTH.get(sig_algo, 0.0)


def is_sm_signature(sig_algo: str) -> bool:
    return sig_algo in SM_SIGNATURES


def is_sha1_signature(sig_algo: str) -> bool:
    return sig_algo in SHA1_SIGNATURES
