"""核心算法 1：X.509 真解析（`cryptography` x509 loader）+ 字段归一。

口径（README §算法 1 同步）：
  * 输入：证书 PEM 字节串（只接受 CERTIFICATE 块；含 PRIVATE KEY 直接拒绝）
  * 解析：subject/issuer DN + CN、SAN、serial、有效期、公钥算法与位数、
          signatureAlgorithm OID -> 名称、SKI/AKI、BasicConstraints(ca)
  * 失败态：
      - PEM 非法 -> 抛 `PemUnparsable`（调用方把证书放进 unparsable 列表，不落库）
      - 公钥曲线不被 cryptography 支持（SM2 / 国密曲线）-> 仍解析其余字段，
        标记 `unsupported_by_crypto_lib=True`，pubkey_algo 用签名 OID 推断为 SM2
      - 时间解析失败 -> 抛 `PemUnparsable`（load 阶段就会失败，不存在"用原文"的分支）
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from src.constants.enums import ChainValidation, PubkeyAlgo
from src.utils.oid_map import SM2_SM3, map_signature_oid
from src.utils.timeutil import as_utc, utcnow

PRIVATE_KEY_MARKERS = (b"PRIVATE KEY", b"BEGIN RSA PRIVATE", b"BEGIN EC PRIVATE")

# SM2 曲线 OID（GM/T 0003），cryptography 不支持 -> 用来识别国密样本
SM_CURVES = {"1.2.156.10197.1.301"}


class PemUnparsable(Exception):
    """PEM 不是合法 X.509 证书。"""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(reason)


class PemPrivateKeyRejected(Exception):
    """PEM 里含私钥 —— 按批次硬约束直接拒绝，绝不入库。"""


@dataclass
class ParsedCertificate:
    subject_cn: str
    issuer_cn: str
    subject_dn: str
    issuer_dn: str
    san: list[str]
    serial: str
    not_before: datetime
    not_after: datetime
    pubkey_algo: str
    key_bits: int | None
    sig_algo: str
    sig_algo_oid: str
    unsupported_by_crypto_lib: bool
    is_ca: bool
    ski: str | None
    aki: str | None
    sha256: str
    days_left: int = 0
    expiry_bucket: str = "normal"
    self_signed: bool = False
    warnings: list[str] = field(default_factory=list)


def assert_not_private_key(pem_bytes: bytes) -> None:
    upper = pem_bytes.upper()
    for marker in PRIVATE_KEY_MARKERS:
        if marker in upper:
            raise PemPrivateKeyRejected("PEM 含私钥内容，拒绝入库")


def _name_cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs:
        return str(attrs[0].value)
    return name.rfc4514_string()


def _get_san(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    values: list[str] = []
    for kind in (x509.DNSName, x509.IPAddress):
        try:
            for value in ext.value.get_values_for_type(kind):
                values.append(str(value))
        except Exception:  # noqa: BLE001 - 某类 SAN 解析失败不影响其它类
            continue
    return values


def _pubkey_info(cert: x509.Certificate, sig_algo: str, sig_oid: str) -> tuple[str, int | None, bool, list[str]]:
    warnings: list[str] = []
    try:
        public_key = cert.public_key()
    except (UnsupportedAlgorithm, ValueError) as exc:
        # SM2/国密曲线的诚实边界：证书本身能解析，但本库/本镜像 OpenSSL 不支持该曲线
        algo = PubkeyAlgo.SM2.value if (SM2_SM3 == sig_algo or "156" in sig_oid) else PubkeyAlgo.UNKNOWN.value
        warnings.append(f"public_key() 不受支持：{type(exc).__name__}")
        return algo, None, True, warnings

    if isinstance(public_key, rsa.RSAPublicKey):
        return PubkeyAlgo.RSA.value, public_key.key_size, False, warnings
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = public_key.curve
        curve_oid = getattr(curve, "dotted_string", "")
        if curve_oid in SM_CURVES:
            return PubkeyAlgo.SM2.value, public_key.key_size, True, warnings
        return PubkeyAlgo.ECDSA.value, public_key.key_size, False, warnings
    warnings.append(f"未识别的公钥类型 {type(public_key).__name__}")
    return PubkeyAlgo.UNKNOWN.value, None, False, warnings


def _ski(cert: x509.Certificate) -> str | None:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        return ext.value.digest.hex().upper()
    except x509.ExtensionNotFound:
        return None


def _aki(cert: x509.Certificate) -> str | None:
    try:
        ext = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    except x509.ExtensionNotFound:
        return None
    if ext.value.key_identifier:
        return ext.value.key_identifier.hex().upper()
    return None


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def parse_pem(pem_text: str, now: datetime | None = None) -> ParsedCertificate:
    """真解析一张 PEM 证书；失败抛 PemUnparsable / PemPrivateKeyRejected。"""
    pem_bytes = pem_text.encode("utf-8") if isinstance(pem_text, str) else pem_text
    if not pem_bytes.strip():
        raise PemUnparsable("empty_pem", "PEM 内容为空")
    assert_not_private_key(pem_bytes)
    if b"BEGIN CERTIFICATE" not in pem_bytes:
        raise PemUnparsable("no_certificate_block", "未找到 BEGIN CERTIFICATE 块")

    try:
        cert = x509.load_pem_x509_certificate(pem_bytes)
    except Exception as exc:  # noqa: BLE001 - 统一收敛为不可解析
        raise PemUnparsable("load_failed", f"{type(exc).__name__}: {exc}") from exc

    sig_oid = cert.signature_algorithm_oid.dotted_string
    sig_algo, recognised = map_signature_oid(sig_oid)
    pubkey_algo, key_bits, unsupported, warnings = _pubkey_info(cert, sig_algo, sig_oid)
    if not recognised:
        warnings.append(f"未识别的签名算法 OID {sig_oid}")

    try:
        not_before = as_utc(cert.not_valid_before_utc)
        not_after = as_utc(cert.not_valid_after_utc)
    except AttributeError:  # pragma: no cover - 兼容旧版 cryptography
        not_before = as_utc(cert.not_valid_before)
        not_after = as_utc(cert.not_valid_after)

    der = cert.public_bytes(serialization.Encoding.DER)
    base = now or utcnow()
    left = (not_after - base).days
    if left < 0:
        bucket = "expired"
    elif left <= 30:
        bucket = "soon_30"
    elif left <= 90:
        bucket = "soon_90"
    else:
        bucket = "normal"

    return ParsedCertificate(
        subject_cn=_name_cn(cert.subject),
        issuer_cn=_name_cn(cert.issuer),
        subject_dn=cert.subject.rfc4514_string(),
        issuer_dn=cert.issuer.rfc4514_string(),
        san=_get_san(cert),
        serial=format(cert.serial_number, "X"),
        not_before=not_before,
        not_after=not_after,
        pubkey_algo=pubkey_algo,
        key_bits=key_bits,
        sig_algo=sig_algo,
        sig_algo_oid=sig_oid,
        unsupported_by_crypto_lib=unsupported,
        is_ca=_is_ca(cert),
        ski=_ski(cert),
        aki=_aki(cert),
        sha256=hashlib.sha256(der).hexdigest(),
        days_left=left,
        expiry_bucket=bucket,
        self_signed=cert.subject == cert.issuer,
        warnings=warnings,
    )


def parse_pem_bytes_with_fallback(pem_text: str) -> tuple[ParsedCertificate | None, str | None]:
    """给批量导入/seed 用：返回 (解析结果, 错误原因)，不抛异常。"""
    try:
        return parse_pem(pem_text), None
    except PemPrivateKeyRejected as exc:
        return None, f"private_key_rejected: {exc}"
    except PemUnparsable as exc:
        return None, f"{exc.reason}: {exc.detail}"


# ==========================================================================
# 算法 1 下半段：链构建 / 链校验 / 时效分级（同属 X.509 审计口径，同文件便于复核）
# ==========================================================================





@dataclass
class ChainLink:
    """链上一张证书的摘要（不落库，返回给前端做可视化）。"""

    cert_id: str
    subject_cn: str
    issuer_cn: str
    is_ca: bool
    self_signed: bool
    sig_algo: str
    key_bits: int | None
    pubkey_algo: str
    not_before: datetime
    not_after: datetime


@dataclass
class ChainResult:
    cert_path: list[str] = field(default_factory=list)
    chain_length: int = 0
    validation: str = ChainValidation.IS_VALID.value
    error_detail: str = ""
    self_signed: bool = False
    root_reached: bool = False
    links: list[ChainLink] = field(default_factory=list)


def _ski_of(cert: ParsedCertificate) -> str | None:
    return cert.ski


def build_chain(
    leaf_id: str,
    leaf: ParsedCertificate,
    pool: list[tuple[str, ParsedCertificate]],
    now: datetime | None = None,
) -> ChainResult:
    """在 pool（(cert_id, parsed)）里按 issuer==subject 建链。"""
    base = now or utcnow()
    result = ChainResult()
    ordered: list[tuple[str, ParsedCertificate]] = [(leaf_id, leaf)]
    visited: set[str] = {leaf.subject_dn}
    current = leaf
    self_signed = leaf.self_signed

    # 最多追 8 层，防环
    for _ in range(8):
        if current.issuer_dn == current.subject_dn:
            result.root_reached = True
            break
        candidate = _find_issuer(current, pool, visited)
        if candidate is None:
            break
        cert_id, parsed = candidate
        ordered.append((cert_id, parsed))
        visited.add(parsed.subject_dn)
        current = parsed
        if parsed.issuer_dn == parsed.subject_dn:
            result.root_reached = True
            break

    result.cert_path = [cid for cid, _ in ordered]
    result.chain_length = len(ordered)
    result.self_signed = self_signed
    result.links = [
        ChainLink(
            cert_id=cid,
            subject_cn=parsed.subject_cn,
            issuer_cn=parsed.issuer_cn,
            is_ca=parsed.is_ca,
            self_signed=parsed.self_signed,
            sig_algo=parsed.sig_algo,
            key_bits=parsed.key_bits,
            pubkey_algo=parsed.pubkey_algo,
            not_before=parsed.not_before,
            not_after=parsed.not_after,
        )
        for cid, parsed in ordered
    ]

    # ---- 校验结论（优先级：incomplete > name_mismatch > expired > is_valid）----
    if leaf.not_after <= base:
        result.validation = ChainValidation.EXPIRED.value
        result.error_detail = f"叶子证书已于 {leaf.not_after.date().isoformat()} 过期"
        return result

    if not result.root_reached:
        missing = "根 CA" if len(ordered) > 1 else "签发 CA"
        result.validation = ChainValidation.INCOMPLETE.value
        result.error_detail = f"链未到达自签根（缺{missing}）；当前链长 {len(ordered)}"
        return result

    result.validation = ChainValidation.IS_VALID.value
    result.error_detail = (
        f"自签证书（信任锚即自身），链长 {len(ordered)}"
        if self_signed
        else f"链完整，长度 {len(ordered)}，已到自签根"
    )
    return result


def name_mismatch(leaf: ParsedCertificate, hostname: str) -> bool:
    """SAN 是否不含端点 hostname（大小写不敏感；DNS SAN 支持 *. 通配单层）。"""
    target = (hostname or "").strip().lower().rstrip(".")
    if not target:
        return True
    for entry in leaf.san:
        value = entry.strip().lower().rstrip(".")
        if not value:
            continue
        if value == target:
            return False
        if value.startswith("*.") and "." in target:
            suffix = value[2:]
            head, _, rest = target.partition(".")
            if rest == suffix and head:
                return False
    return True


def apply_name_match(result: ChainResult, leaf: ParsedCertificate, hostname: str) -> ChainResult:
    """链结论确定后，再按 hostname 覆写为 name_mismatch（优先级高于 is_valid、低于 incomplete）。"""
    if result.validation == ChainValidation.IS_VALID.value and name_mismatch(leaf, hostname):
        result.validation = ChainValidation.NAME_MISMATCH.value
        result.error_detail = (
            f"SAN={leaf.san or ['(空)']} 不包含端点主机名 {hostname}"
        )
    return result


def chain_trust_score(result: ChainResult) -> float:
    """chain_trust 分量：完整已验证 1.0 / self_signed 0.3 / incomplete 0.5。"""
    if result.self_signed:
        return 0.3
    if result.validation == ChainValidation.INCOMPLETE.value or not result.root_reached:
        return 0.5
    return 1.0


def _find_issuer(
    child: ParsedCertificate,
    pool: list[tuple[str, ParsedCertificate]],
    visited: set[str],
) -> tuple[str, ParsedCertificate] | None:
    for cert_id, parsed in pool:
        if parsed.subject_dn in visited:
            continue
        if parsed.subject_dn != child.issuer_dn:
            continue
        # 双方都有 AKI/SKI 时必须匹配，防止"同名不同 CA"错连
        if child.aki and parsed.ski and child.aki != parsed.ski:
            continue
        return cert_id, parsed
    return None
