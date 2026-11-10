"""幂等演示数据：`docker compose exec -T backend python -m scripts.seed_demo`。

场景：云栖省政务云密码应用中心（12 厅局 / 40 个 TLS 端点 / 52 张证书 / 18 条链）。

**全部为合成数据**：证书来自 `backend/fixtures/certs/` 的真实 PEM（自签/合成 CA 签发，
不含任何私钥）与 seed 运行时用 `cryptography` 确定性生成的证书；不连接任何真实 CA、
不做真实 TLS 握手。固定 serial 与绝对日期（锚定 2026-11-10）保证分档可复现。

自然键（重复执行只打印 SEED_SKIPPED，不覆盖用户改动）：
  User.email / TlsEndpoint(hostname, port) / CertificateAsset.cert_key /
  ChainRecord.endpoint_id / AlgorithmAssessment.certificate_id /
  MigrationItem.certificate_id / InventoryExport.name / AuditLog(action, entity_id)

末尾打印**恰好一行** `SEED_SUMMARY {json}`（键排序固定，两次运行必须逐字一致）。
"""
from __future__ import annotations

import datetime as dt
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src.config.database import session_scope
from src.config.settings import settings
from src.constants.enums import (
    CertSource,
    DeptGrade,
    EndpointRisk,
    MigrationPriority,
    MigrationStatus,
)
from src.constants.roles import ROLE_ADMIN, ROLE_ENGINEER, ROLE_OWNER
from src.models.algorithm_assessment import AlgorithmAssessment
from src.models.audit_log import AuditLog
from src.models.certificate_asset import CertificateAsset
from src.models.chain_record import ChainRecord
from src.models.inventory_export import InventoryExport
from src.models.migration_item import MigrationItem
from src.models.tls_endpoint import TlsEndpoint
from src.models.user import User
from src.services import assessment_service, migration_service
from src.services.x509_audit import parse_pem
from src.utils.password import hash_password
from src.utils.timeutil import CERT_ANCHOR_DATE, utcnow

DEMO_PASSWORD = "Demo@2026"
FIXTURES = Path(settings.cert_fixtures_dir)
UTC = dt.timezone.utc
ORG = "YunQi Provincial E-Government Crypto Center"

DEMO_USERS = [
    ("admin@cryptoinv.demo", "云栖省密码应用中心 · 管理员", ROLE_ADMIN, None),
    ("engineer@cryptoinv.demo", "云栖省密码应用中心 · 密码资产工程师", ROLE_ENGINEER, None),
    ("owner@cryptoinv.demo", "省人社厅 · 资产责任人", ROLE_OWNER, "省人社厅"),
]

# 12 个厅局（dept, 系统名, dept_grade）
DEPARTMENTS: list[tuple[str, str, str]] = [
    ("省人社厅", "社保公共服务平台", DeptGrade.A.value),
    ("省医保局", "医保结算中心", DeptGrade.A.value),
    ("省公积金中心", "住房公积金网厅", DeptGrade.A.value),
    ("省税务局", "电子税务局", DeptGrade.A.value),
    ("省交管局", "交管互联网服务平台", DeptGrade.A.value),
    ("省教育厅", "教育政务服务网", DeptGrade.B.value),
    ("省卫健委", "健康云服务平台", DeptGrade.A.value),
    ("省民政厅", "民政一体化政务平台", DeptGrade.B.value),
    ("省自然资源厅", "不动产登记平台", DeptGrade.B.value),
    ("省市场监管局", "一网通办企业登记", DeptGrade.B.value),
    ("省文旅厅", "文旅政务公开平台", DeptGrade.C.value),
    ("省应急管理厅", "应急指挥信息网", DeptGrade.C.value),
]
DEPT_GRADE = {dept: grade for dept, _system, grade in DEPARTMENTS}
DEPT_SYSTEM = {dept: system for dept, system, _grade in DEPARTMENTS}

# 40 个端点：hostname, port, dept, internet_facing, 是否已登记证书（其余为"待扫描"）
ENDPOINTS: list[tuple[str, int, str, bool, bool]] = [
    ("www.rj.yunqi-gov.example", 443, "省人社厅", True, True),
    ("self.hr.yunqi-gov.example", 443, "省人社厅", False, True),
    ("sso.rj.yunqi-gov.example", 443, "省人社厅", True, True),
    ("api.rj.yunqi-gov.example", 8443, "省人社厅", False, False),
    ("legacy.ybj.yunqi-gov.example", 443, "省医保局", True, True),
    ("api.ybj.yunqi-gov.example", 443, "省医保局", True, False),
    ("settle.ybj.yunqi-gov.example", 443, "省医保局", True, True),
    ("query.ybj.yunqi-gov.example", 8443, "省医保局", False, False),
    ("www.gjj.yunqi-gov.example", 443, "省公积金中心", True, True),
    ("api.gjj.yunqi-gov.example", 443, "省公积金中心", True, False),
    ("probe.gjj.yunqi-gov.example", 8443, "省公积金中心", False, False),
    ("old.tax.yunqi-gov.example", 443, "省税务局", True, True),
    ("api.tax.yunqi-gov.example", 443, "省税务局", True, True),
    ("etax.tax.yunqi-gov.example", 8443, "省税务局", True, False),
    ("fapiao.tax.yunqi-gov.example", 443, "省税务局", False, False),
    ("expired.jt.yunqi-gov.example", 443, "省交管局", True, True),
    ("svc.ga.yunqi-gov.example", 443, "省交管局", True, True),
    ("api.jt.yunqi-gov.example", 8443, "省交管局", True, False),
    ("ecdsa.jy.yunqi-gov.example", 443, "省教育厅", True, True),
    ("api.jy.yunqi-gov.example", 443, "省教育厅", False, False),
    ("zk.jy.yunqi-gov.example", 443, "省教育厅", True, False),
    ("health.wsj.yunqi-gov.example", 443, "省卫健委", True, True),
    ("api.wsj.yunqi-gov.example", 443, "省卫健委", False, False),
    ("yc.wsj.yunqi-gov.example", 443, "省卫健委", True, False),
    ("pm.wsj.yunqi-gov.example", 8443, "省卫健委", True, False),
    ("soon.mz.yunqi-gov.example", 443, "省民政厅", False, True),
    ("gm.mz.yunqi-gov.example", 443, "省民政厅", True, True),
    ("jz.mz.yunqi-gov.example", 8443, "省民政厅", False, False),
    ("api.zr.yunqi-gov.example", 443, "省自然资源厅", True, True),
    ("bd.zr.yunqi-gov.example", 443, "省自然资源厅", True, False),
    ("map.zr.yunqi-gov.example", 8443, "省自然资源厅", False, False),
    ("api.sc.yunqi-gov.example", 443, "省市场监管局", False, True),
    ("biz.sc.yunqi-gov.example", 443, "省市场监管局", True, False),
    ("gs.sc.yunqi-gov.example", 8443, "省市场监管局", False, False),
    ("api.wl.yunqi-gov.example", 443, "省文旅厅", False, True),
    ("tour.wl.yunqi-gov.example", 443, "省文旅厅", True, False),
    ("data.wl.yunqi-gov.example", 8443, "省文旅厅", False, False),
    ("api.yj.yunqi-gov.example", 443, "省应急管理厅", False, True),
    ("cmd.yj.yunqi-gov.example", 8443, "省应急管理厅", False, False),
    ("res.yj.yunqi-gov.example", 443, "省应急管理厅", True, False),
]

TLS_MODERN = ["TLS1.3", "TLS1.2"]
TLS_LEGACY = ["TLS1.2", "TLS1.1"]
CIPHER_MODERN = ["TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384"]
CIPHER_LEGACY = ["ECDHE-RSA-AES128-SHA", "AES128-SHA"]


@dataclass
class CertSpec:
    """一张要入库的证书（fixture 或生成）。"""

    cert_key: str
    pem: str
    hostname: str | None  # None = CA 证书（不挂端点）
    active: bool = True
    source: str = CertSource.IMPORT.value


# ---------------------------------------------------------------- 生成 CA ----


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _new_key(kind: str):
    if kind == "RSA1024":
        return rsa.generate_private_key(public_exponent=65537, key_size=1024)
    if kind == "ECDSA256":
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_ca(cn: str, key, issuer_name: x509.Name, issuer_key, serial: int, nb, na, self_signed: bool):
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if not self_signed:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _build_leaf(
    cn: str,
    sans: list[str],
    key,
    issuer_cert: x509.Certificate,
    issuer_key,
    serial: int,
    not_before: dt.datetime,
    not_after: dt.datetime,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    )
    return builder.sign(issuer_key, hashes.SHA256())


@dataclass
class CaMaterial:
    gen_root_cert: x509.Certificate
    gen_root_key: Any
    gen_int_cert: x509.Certificate
    gen_int_key: Any
    ext_int_cert: x509.Certificate
    ext_int_key: Any


BASE = CERT_ANCHOR_DATE


def build_ca_material() -> CaMaterial:
    """在内存里生成演示 CA（私钥只存在于本进程，不落库、不入仓库）。"""
    gen_root_key = _new_key("RSA2048")
    gen_root_cert = _build_ca(
        "YunQi Gov Cloud Demo Root CA G3",
        gen_root_key,
        _name("YunQi Gov Cloud Demo Root CA G3"),
        gen_root_key,
        0x5610A00000000001,
        BASE - dt.timedelta(days=700),
        BASE + dt.timedelta(days=2600),
        self_signed=True,
    )
    gen_int_key = _new_key("RSA2048")
    gen_int_cert = _build_ca(
        "YunQi Gov Cloud Demo Issuing CA G3",
        gen_int_key,
        gen_root_cert.subject,
        gen_root_key,
        0x5610A00000000002,
        BASE - dt.timedelta(days=500),
        BASE + dt.timedelta(days=1800),
        self_signed=False,
    )
    # 外部/未登记的 CA：其根证书**不入库**，用来演示 incomplete 链
    ext_root_key = _new_key("RSA2048")
    ext_root_cert = _build_ca(
        "Third Party Legacy Root CA (未登记)",
        ext_root_key,
        _name("Third Party Legacy Root CA (未登记)"),
        ext_root_key,
        0x5610A00000000003,
        BASE - dt.timedelta(days=900),
        BASE + dt.timedelta(days=1500),
        self_signed=True,
    )
    ext_int_key = _new_key("RSA2048")
    ext_int_cert = _build_ca(
        "Third Party Legacy Issuing CA (未登记根)",
        ext_int_key,
        ext_root_cert.subject,
        ext_root_key,
        0x5610A00000000004,
        BASE - dt.timedelta(days=400),
        BASE + dt.timedelta(days=1200),
        self_signed=False,
    )
    return CaMaterial(gen_root_cert, gen_root_key, gen_int_cert, gen_int_key, ext_int_cert, ext_int_key)


def _fixture(name: str) -> str:
    """读取随仓库提交的真实 PEM 样本（只含 CERTIFICATE 块，无私钥）。"""
    return (FIXTURES / name).read_text(encoding="utf-8")


# 链端点（18 个）：叶子证书来源（fixture 或生成参数）
CHAIN_LEAVES: list[dict[str, Any]] = [
    {"host": "www.rj.yunqi-gov.example", "fixture": "leaf_ok.pem"},
    {"host": "self.hr.yunqi-gov.example", "fixture": "leaf_selfsigned.pem"},
    {"host": "sso.rj.yunqi-gov.example", "gen": {"cn": "sso.rj.yunqi-gov.example",
        "sans": ["sso.rj.yunqi-gov.example", "login.rj.yunqi-gov.example", "auth.rj.yunqi-gov.example"],
        "key": "RSA1024", "issuer": "ext_int", "offset_before": -700, "offset_after": 30}},
    {"host": "legacy.ybj.yunqi-gov.example", "fixture": "leaf_sha1.pem"},
    {"host": "settle.ybj.yunqi-gov.example", "gen": {"cn": "settle.ybj.yunqi-gov.example",
        "sans": ["settle.ybj.yunqi-gov.example", "pay.ybj.yunqi-gov.example", "m.ybj.yunqi-gov.example"],
        "key": "RSA1024", "issuer": "gen_int", "offset_before": -800, "offset_after": -20}},
    {"host": "www.gjj.yunqi-gov.example", "gen": {"cn": "www.gjj.yunqi-gov.example",
        "sans": ["www.gjj.yunqi-gov.example", "gjj.yunqi-gov.example", "m.gjj.yunqi-gov.example"],
        "key": "RSA2048", "issuer": "gen_int", "offset_before": -700, "offset_after": -15}},
    {"host": "old.tax.yunqi-gov.example", "fixture": "leaf_rsa1024.pem"},
    {"host": "api.tax.yunqi-gov.example", "gen": {"cn": "api.tax.yunqi-gov.example",
        "sans": ["api.tax.yunqi-gov.example"], "key": "RSA1024", "issuer": "ext_int",
        "offset_before": -900, "offset_after": 30}},
    {"host": "expired.jt.yunqi-gov.example", "fixture": "leaf_expired.pem"},
    {"host": "svc.ga.yunqi-gov.example", "fixture": "leaf_name_mismatch.pem"},
    {"host": "ecdsa.jy.yunqi-gov.example", "fixture": "leaf_ecdsa_p256.pem"},
    {"host": "health.wsj.yunqi-gov.example", "gen": {"cn": "health.wsj.yunqi-gov.example",
        "sans": ["health.wsj.yunqi-gov.example", "app.wsj.yunqi-gov.example", "m.wsj.yunqi-gov.example"],
        "key": "RSA1024", "issuer": "ext_int", "offset_before": -600, "offset_after": 24}},
    {"host": "soon.mz.yunqi-gov.example", "fixture": "leaf_expiring30.pem"},
    {"host": "gm.mz.yunqi-gov.example", "fixture": "leaf_sm2.pem"},
    {"host": "api.zr.yunqi-gov.example", "gen": {"cn": "api.zr.yunqi-gov.example",
        "sans": ["other.zr.yunqi-gov.example"], "key": "RSA2048", "issuer": "gen_int",
        "offset_before": -300, "offset_after": 240}},
    {"host": "api.sc.yunqi-gov.example", "gen": {"cn": "api.sc.yunqi-gov.example",
        "sans": ["api.sc.yunqi-gov.example", "biz.sc.yunqi-gov.example", "gs.sc.yunqi-gov.example"],
        "key": "RSA1024", "issuer": "gen_int", "offset_before": -400, "offset_after": 66}},
    {"host": "api.wl.yunqi-gov.example", "gen": {"cn": "api.wl.yunqi-gov.example",
        "sans": ["api.wl.yunqi-gov.example"], "key": "RSA2048", "issuer": "gen_int",
        "offset_before": -200, "offset_after": 400}},
    {"host": "api.yj.yunqi-gov.example", "gen": {"cn": "api.yj.yunqi-gov.example",
        "sans": ["api.yj.yunqi-gov.example"], "key": "RSA2048", "issuer": "gen_int",
        "offset_before": -150, "offset_after": 520}},
]

# 29 张历史证书（is_active=False，仍参与评估但不进迁移清单）
ARCHIVED_CERTS: list[dict[str, Any]] = [
    {"host": "www.rj.yunqi-gov.example", "bucket": "expired", "key": "RSA1024", "issuer": "gen_int"},
    {"host": "www.rj.yunqi-gov.example", "bucket": "soon90", "key": "RSA2048", "issuer": "gen_int"},
    {"host": "www.rj.yunqi-gov.example", "bucket": "soon30", "key": "ECDSA256", "issuer": "gen_int"},
    {"host": "sso.rj.yunqi-gov.example", "bucket": "normal", "key": "RSA2048", "issuer": "gen_int"},
    {"host": "api.rj.yunqi-gov.example", "bucket": "soon90", "key": "RSA2048", "issuer": "ext_int"},
    {"host": "legacy.ybj.yunqi-gov.example", "bucket": "expired", "key": "RSA2048", "issuer": "gen_int"},
    {"host": "settle.ybj.yunqi-gov.example", "bucket": "soon90", "key": "RSA1024", "issuer": "gen_int"},
    {"host": "query.ybj.yunqi-gov.example", "bucket": "soon30", "key": "RSA2048", "issuer": "gen_int"},
    {"host": "www.gjj.yunqi-gov.example", "bucket": "expired", "key": "RSA2048", "issuer": "ext_int"},
    {"host": "api.gjj.yunqi-gov.example", "bucket": "soon90", "key": "RSA1024", "issuer": "gen_int"},
    {"host": "probe.gjj.yunqi-gov.example", "bucket": "normal", "key": "RSA2048", "issuer": "gen_int"},
    {"host": "old.tax.yunqi-gov.example", "bucket": "expired", "key": "RSA1024", "issuer": "gen_int"},
    {"host": "api.tax.yunqi-gov.example", "bucket": "soon90", "key": "RSA2048", "issuer": "gen_int"},
    {"host": "etax.tax.yunqi-gov.example", "bucket": "expired", "key": "RSA2048", "issuer": "gen_int"},
    {"host": "fapiao.tax.yunqi-gov.example", "bucket": "soon90", "key": "ECDSA256", "issuer": "gen_int"},
    {"host": "expired.jt.yunqi-gov.example", "bucket": "expired", "key": "RSA2048", "issuer": "ext_int"},
    {"host": "api.jt.yunqi-gov.example", "bucket": "soon30", "key": "RSA1024", "issuer": "gen_int"},
    {"host": "ecdsa.jy.yunqi-gov.example", "bucket": "soon90", "key": "RSA2048", "issuer": "gen_int"},
    {"host": "zk.jy.yunqi-gov.example", "bucket": "normal", "key": "RSA2048", "issuer": "gen_int"},
    {"host": "health.wsj.yunqi-gov.example", "bucket": "expired", "key": "RSA1024", "issuer": "gen_int"},
    {"host": "yc.wsj.yunqi-gov.example", "bucket": "soon30", "key": "RSA2048", "issuer": "ext_int"},
    {"host": "soon.mz.yunqi-gov.example", "bucket": "soon90", "key": "RSA2048", "issuer": "gen_int"},
    {"host": "jz.mz.yunqi-gov.example", "bucket": "expired", "key": "RSA2048", "issuer": "gen_int"},
    {"host": "api.zr.yunqi-gov.example", "bucket": "expired", "key": "RSA1024", "issuer": "gen_int"},
    {"host": "map.zr.yunqi-gov.example", "bucket": "soon90", "key": "RSA2048", "issuer": "gen_int"},
    {"host": "api.sc.yunqi-gov.example", "bucket": "normal", "key": "RSA1024", "issuer": "gen_int"},
    {"host": "api.wl.yunqi-gov.example", "bucket": "normal", "key": "RSA2048", "issuer": "gen_int"},
    {"host": "tour.wl.yunqi-gov.example", "bucket": "normal", "key": "RSA2048", "issuer": "gen_int"},
    {"host": "cmd.yj.yunqi-gov.example", "bucket": "normal", "key": "RSA2048", "issuer": "gen_int"},
]
ARCHIVED_OFFSETS = {
    "expired": (-500, -30),
    "soon30": (-300, 30),
    "soon90": (-300, 88),
    "normal": (-200, 720),
}

# 14 条迁移项（P0 4 / P1 5 / P2 3 / P3 2）；优先级由算法真实计算，这里只指定入选证书
MIGRATION_CHAIN_HOSTS = [
    "sso.rj.yunqi-gov.example",        # P0
    "settle.ybj.yunqi-gov.example",    # P0
    "api.tax.yunqi-gov.example",       # P0
    "health.wsj.yunqi-gov.example",    # P0
    "www.gjj.yunqi-gov.example",       # P1
    "old.tax.yunqi-gov.example",       # P1
    "expired.jt.yunqi-gov.example",    # P1
    "soon.mz.yunqi-gov.example",       # P1
    "api.sc.yunqi-gov.example",        # P1
    "legacy.ybj.yunqi-gov.example",    # P2（SHA-1）
    "svc.ga.yunqi-gov.example",        # P2（name_mismatch）
    "www.rj.yunqi-gov.example",        # P2（国密改造窗口）
    "api.wl.yunqi-gov.example",        # P3
    "api.yj.yunqi-gov.example",        # P3
]

SEED_EXPORTS = [
    ("2026Q3 密码资产全量盘点（密评送审）", "all", "csv", 52),
    ("省人社厅密码资产盘点（厅局自用）", "dept", "json", 8),
    ("国密改造迁移清单（2026Q4 批次）", "all", "csv", 14),
]

AUDIT_SEEDS = [
    ("auth.login", "User", "owner@cryptoinv.demo", {"role": ROLE_OWNER}),
    ("auth.login", "User", "engineer@cryptoinv.demo", {"role": ROLE_ENGINEER}),
    ("auth.login", "User", "admin@cryptoinv.demo", {"role": ROLE_ADMIN}),
    ("certificate.import", "CertificateAsset", "imp-1", {"source": "import", "batch": "2026Q3"}),
    ("certificate.import", "CertificateAsset", "imp-2", {"source": "import", "batch": "2026Q3"}),
    ("endpoint.scan", "TlsEndpoint", "scan-1", {"simulated": True}),
    ("endpoint.scan", "TlsEndpoint", "scan-2", {"simulated": True}),
    ("assessment.run", "AlgorithmAssessment", "seed-run-1", {"mode": "inline"}),
    ("assessment.run", "AlgorithmAssessment", "seed-run-2", {"mode": "worker"}),
    ("migration.generate", "MigrationItem", "seed-gen-1", {"created": 14}),
    ("migration.transition", "MigrationItem", "seed-tr-1", {"status": "scheduled"}),
    ("migration.transition", "MigrationItem", "seed-tr-2", {"status": "in_progress"}),
    ("migration.export", "MigrationItem", "seed-exp-1", {"rows": 14}),
    ("export.create", "InventoryExport", "seed-out-1", {"rows": 52, "format": "csv"}),
    ("export.create", "InventoryExport", "seed-out-2", {"rows": 14, "format": "csv"}),
    ("authz.denied", "Route", "POST /api/exports", {"role": ROLE_OWNER}),
    ("authz.denied", "Route", "POST /api/migration/generate", {"role": ROLE_OWNER}),
    ("assessments.run", "AlgorithmAssessment", "seed-run-3", {"mode": "inline"}),
    ("certificate.import", "CertificateAsset", "imp-3", {"source": "import", "unparsable": 1}),
    ("endpoint.scan", "TlsEndpoint", "scan-3", {"simulated": True}),
]

CREATED = 0
SKIPPED = 0


def _log(kind: str, entity: str, key: str) -> None:
    global CREATED, SKIPPED
    if kind == "SEED_CREATED":
        CREATED += 1
    else:
        SKIPPED += 1
    print(f"{kind} entity={entity} key={key}", flush=True)


def _created(entity: str, key: str) -> None:
    _log("SEED_CREATED", entity, key)


def _skipped(entity: str, key: str) -> None:
    _log("SEED_SKIPPED", entity, key)


# ------------------------------------------------------------------ 账号 ----


def seed_users(db) -> dict[str, User]:
    users: dict[str, User] = {}
    for email, display_name, role, dept in DEMO_USERS:
        user = db.query(User).filter(User.email == email).one_or_none()
        if user is None:
            user = User(
                email=email,
                password_hash=hash_password(DEMO_PASSWORD),
                display_name=display_name,
                role=role,
                dept=dept,
                is_active=True,
            )
            db.add(user)
            db.flush()
            _created("User", email)
        else:
            _skipped("User", email)
        users[role] = user
    return users


# ------------------------------------------------------------------ 端点 ----


def seed_endpoints(db) -> dict[str, TlsEndpoint]:
    endpoints: dict[str, TlsEndpoint] = {}
    for index, (hostname, port, dept, internet, scanned) in enumerate(ENDPOINTS):
        existing = (
            db.query(TlsEndpoint)
            .filter(TlsEndpoint.hostname == hostname, TlsEndpoint.port == port)
            .one_or_none()
        )
        if existing is not None:
            _skipped("TlsEndpoint", f"{hostname}:{port}")
            endpoints[hostname] = existing
            continue
        legacy = index % 7 == 0
        endpoint = TlsEndpoint(
            hostname=hostname,
            port=port,
            ip=f"10.{20 + index % 12}.{index % 250}.{11 + index % 200}",
            dept=dept,
            system_name=DEPT_SYSTEM[dept],
            dept_grade=DEPT_GRADE[dept],
            internet_facing=internet,
            tls_versions=list(TLS_LEGACY if legacy else TLS_MODERN) if scanned else [],
            cipher_suites=list(CIPHER_LEGACY if legacy else CIPHER_MODERN) if scanned else [],
            last_scanned_at=(utcnow() - dt.timedelta(days=3 + index % 17)) if scanned else None,
            risk_level=(
                EndpointRisk.HIGH.value
                if legacy
                else (EndpointRisk.LOW.value if internet else EndpointRisk.MEDIUM.value)
            ),
            simulated=True,
        )
        db.add(endpoint)
        db.flush()
        endpoints[hostname] = endpoint
        _created("TlsEndpoint", f"{hostname}:{port}")
    return endpoints


# ------------------------------------------------------------ 证书装配 ----


def _fixture_specs() -> list[CertSpec]:
    specs: list[CertSpec] = []
    # CA 证书（不挂端点，作为全局链池）
    for name, key in (("root_ca.pem", "fx-root_ca"), ("intermediate_ca.pem", "fx-intermediate_ca")):
        specs.append(
            CertSpec(cert_key=key, pem=_fixture(name), hostname=None, active=False)
        )
    mapping = {
        "leaf_ok.pem": "www.rj.yunqi-gov.example",
        "leaf_selfsigned.pem": "self.hr.yunqi-gov.example",
        "leaf_sha1.pem": "legacy.ybj.yunqi-gov.example",
        "leaf_rsa1024.pem": "old.tax.yunqi-gov.example",
        "leaf_expired.pem": "expired.jt.yunqi-gov.example",
        "leaf_expiring30.pem": "soon.mz.yunqi-gov.example",
        "leaf_sm2.pem": "gm.mz.yunqi-gov.example",
        "leaf_ecdsa_p256.pem": "ecdsa.jy.yunqi-gov.example",
        "leaf_name_mismatch.pem": "svc.ga.yunqi-gov.example",
    }
    for filename, hostname in mapping.items():
        specs.append(
            CertSpec(
                cert_key=f"fx-{filename.replace('.pem', '')}",
                pem=_fixture(filename),
                hostname=hostname,
            )
        )
    return specs


def _generated_specs(ca: CaMaterial) -> list[CertSpec]:
    specs: list[CertSpec] = []
    issuer_map = {
        "gen_int": (ca.gen_int_cert, ca.gen_int_key),
        "ext_int": (ca.ext_int_cert, ca.ext_int_key),
    }

    # CA 证书：gen_root / gen_int / ext_int（ext_root 故意不入库 -> incomplete 链）
    specs.append(CertSpec("gen-root-ca", _pem(ca.gen_root_cert), None, False))
    specs.append(CertSpec("gen-intermediate-ca", _pem(ca.gen_int_cert), None, False))
    specs.append(CertSpec("gen-ext-intermediate-ca", _pem(ca.ext_int_cert), None, False))

    serial = 0x5610B00000000000
    for item in CHAIN_LEAVES:
        if "gen" not in item:
            continue
        gen = item["gen"]
        issuer_cert, issuer_key = issuer_map[gen["issuer"]]
        serial += 1
        cert = _build_leaf(
            gen["cn"],
            gen["sans"],
            _new_key(gen["key"]),
            issuer_cert,
            issuer_key,
            serial,
            BASE + dt.timedelta(days=gen["offset_before"]),
            BASE + dt.timedelta(days=gen["offset_after"]),
        )
        specs.append(
            CertSpec(cert_key=f"gen-chain-{item['host']}", pem=_pem(cert), hostname=item["host"])
        )

    for index, item in enumerate(ARCHIVED_CERTS):
        serial += 1
        before, after = ARCHIVED_OFFSETS[item["bucket"]]
        issuer_cert, issuer_key = issuer_map[item["issuer"]]
        jitter = index % 5
        host = item["host"]
        label = host.split(".")[0]
        cert = _build_leaf(
            f"legacy-{label}-{index:02d}.yunqi-gov.example",
            [f"legacy-{label}-{index:02d}.yunqi-gov.example", host],
            _new_key(item["key"]),
            issuer_cert,
            issuer_key,
            serial,
            BASE + dt.timedelta(days=before),
            BASE + dt.timedelta(days=after - jitter),
        )
        specs.append(
            CertSpec(cert_key=f"gen-arch-{index:02d}-{host}", pem=_pem(cert), hostname=host, active=False)
        )
    return specs


def seed_certificates(db, endpoints: dict[str, TlsEndpoint], ca: CaMaterial) -> dict[str, CertificateAsset]:
    certs: dict[str, CertificateAsset] = {}
    specs = _fixture_specs() + _generated_specs(ca)
    for spec in specs:
        existing = (
            db.query(CertificateAsset).filter(CertificateAsset.cert_key == spec.cert_key).one_or_none()
        )
        if existing is not None:
            _skipped("CertificateAsset", spec.cert_key)
            certs[spec.cert_key] = existing
            continue
        parsed = parse_pem(spec.pem)
        endpoint = endpoints.get(spec.hostname) if spec.hostname else None
        if spec.hostname and endpoint is None:
            raise RuntimeError(f"端点不存在：{spec.hostname}")
        cert = CertificateAsset(
            endpoint_id=endpoint.id if endpoint else None,
            cert_key=spec.cert_key,
            pem=spec.pem,
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
            source=spec.source,
            is_active=spec.active,
        )
        db.add(cert)
        db.flush()
        certs[spec.cert_key] = cert
        _created("CertificateAsset", spec.cert_key)
    return certs


def seed_unparsable() -> int:
    """非法 PEM 走「不可解析清单」路径，不落库（证明失败态真实存在）。"""
    corrupt = (__import__("pathlib").Path(FIXTURES) / "invalid_corrupt.pem").read_text(encoding="utf-8")
    try:
        parse_pem(corrupt)
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"SEED_UNPARSABLE file=invalid_corrupt.pem reason={type(exc).__name__}", flush=True)
        return 1


# ------------------------------------------------------------ 评估/迁移 ----


def seed_migration(db, certs: dict[str, CertificateAsset]) -> dict[str, int]:
    counts = {p.value: 0 for p in MigrationPriority}
    for host in MIGRATION_CHAIN_HOSTS:
        key = f"gen-chain-{host}" if f"gen-chain-{host}" in certs else f"fx-{_fixture_key_for_host(host)}"
        cert = certs.get(key)
        if cert is None:
            raise RuntimeError(f"迁移清单证书缺失：{key}")
        existing = (
            db.query(MigrationItem).filter(MigrationItem.certificate_id == cert.id).one_or_none()
        )
        if existing is not None:
            counts[existing.priority] = counts.get(existing.priority, 0) + 1
            _skipped("MigrationItem", key)
            continue
        item = migration_service.create_item(db, certificate_id=str(cert.id), actor=None)  # type: ignore[arg-type]
        counts[item.priority] = counts.get(item.priority, 0) + 1
        _created("MigrationItem", f"{key}->{item.priority}")
    # 预置 1 条已排期状态，演示状态机推进（seed 不覆盖已有状态）
    scheduled = 0
    for host in ("www.gjj.yunqi-gov.example",):
        cert = certs.get(f"gen-chain-{host}")
        if cert is None:
            continue
        item = db.query(MigrationItem).filter(MigrationItem.certificate_id == cert.id).one_or_none()
        if item is not None and item.status == MigrationStatus.TODO.value:
            item.status = MigrationStatus.SCHEDULED.value
            item.planned_at = utcnow()
            scheduled += 1
    if scheduled:
        print(f"SEED_STATE migration scheduled={scheduled}", flush=True)
    return counts


def _fixture_key_for_host(host: str) -> str:
    mapping = {
        "www.rj.yunqi-gov.example": "leaf_ok",
        "self.hr.yunqi-gov.example": "leaf_selfsigned",
        "legacy.ybj.yunqi-gov.example": "leaf_sha1",
        "old.tax.yunqi-gov.example": "leaf_rsa1024",
        "expired.jt.yunqi-gov.example": "leaf_expired",
        "soon.mz.yunqi-gov.example": "leaf_expiring30",
        "gm.mz.yunqi-gov.example": "leaf_sm2",
        "ecdsa.jy.yunqi-gov.example": "leaf_ecdsa_p256",
        "svc.ga.yunqi-gov.example": "leaf_name_mismatch",
    }
    return mapping[host]


def seed_exports(db, users: dict[str, User]) -> int:
    created = 0
    for name, scope, fmt, rows in SEED_EXPORTS:
        existing = db.query(InventoryExport).filter(InventoryExport.name == name).one_or_none()
        if existing is not None:
            _skipped("InventoryExport", name)
            continue
        db.add(
            InventoryExport(
                name=name,
                scope=scope,
                export_format=fmt,
                rows=rows,
                filters={"scope": scope, "format": fmt},
                generated_by=users[ROLE_ADMIN].email,
                generated_at=utcnow() - dt.timedelta(days=len(name) % 5 + 1),
            )
        )
        _created("InventoryExport", name)
        created += 1
    return created


def seed_audit(db, users: dict[str, User]) -> int:
    created = 0
    for index, (action, entity, entity_id, payload) in enumerate(AUDIT_SEEDS):
        # 真实请求也会写同 action/entity_id 的审计行（如 owner 越权 403），
        # 这里只要"已存在 seed 行"就跳过，用 first() 避免多行时抛 MultipleResultsFound。
        existing = (
            db.query(AuditLog)
            .filter(AuditLog.action == action, AuditLog.entity_id == entity_id)
            .first()
        )
        if existing is not None:
            _skipped("AuditLog", f"{action}:{entity_id}")
            continue
        actor = users[ROLE_ADMIN]
        if "owner" in str(payload.get("role", "")):
            actor = users[ROLE_OWNER]
        elif "engineer" in str(payload.get("role", "")):
            actor = users[ROLE_ENGINEER]
        db.add(
            AuditLog(
                actor_id=actor.id,
                action=action,
                entity_type=entity,
                entity_id=entity_id,
                payload_json=payload,
                ip=f"10.30.{(index % 12) + 1}.{(index % 200) + 11}",
                trace_id=f"seed{index:04d}",
                created_at=utcnow() - dt.timedelta(minutes=(len(AUDIT_SEEDS) - index) * 17),
            )
        )
        _created("AuditLog", f"{action}:{entity_id}")
        created += 1
    return created


# ------------------------------------------------------------------ 汇总 ----


def summary_counts(db) -> dict[str, Any]:
    from src.models.algorithm_assessment import AlgorithmAssessment as AA
    from src.models.chain_record import ChainRecord as CR

    expired = soon30 = soon90 = normal = 0
    for cert in db.query(CertificateAsset).all():
        left = (cert.not_after - utcnow()).days
        if left < 0:
            expired += 1
        elif left <= 30:
            soon30 += 1
        elif left <= 90:
            soon90 += 1
        else:
            normal += 1
    chains = db.query(CR).all()
    migration = {p.value: 0 for p in MigrationPriority}
    for item in db.query(MigrationItem).all():
        migration[item.priority] = migration.get(item.priority, 0) + 1
    return {
        "users": db.query(User).count(),
        "endpoints": db.query(TlsEndpoint).count(),
        "certificates": db.query(CertificateAsset).count(),
        "chains": len(chains),
        "assessments": db.query(AA).count(),
        "migration_items": db.query(MigrationItem).count(),
        "migration_p0": migration[MigrationPriority.P0.value],
        "migration_p1": migration[MigrationPriority.P1.value],
        "migration_p2": migration[MigrationPriority.P2.value],
        "migration_p3": migration[MigrationPriority.P3.value],
        "exports": db.query(InventoryExport).count(),
        "audit_logs": db.query(AuditLog).count(),
        "chain_valid": sum(1 for c in chains if c.validation == "is_valid"),
        "chain_expired": sum(1 for c in chains if c.validation == "expired"),
        "chain_name_mismatch": sum(1 for c in chains if c.validation == "name_mismatch"),
        "chain_incomplete": sum(1 for c in chains if c.validation == "incomplete"),
        "expired": expired,
        "soon30": soon30,
        "soon90": soon90,
        "normal": normal,
    }


EXPECTED = {
    "users": 3,
    "endpoints": 40,
    "certificates": 52,
    "chains": 18,
    "assessments": 52,
    "migration_items": 14,
    "migration_p0": 4,
    "migration_p1": 5,
    "migration_p2": 3,
    "migration_p3": 2,
    "exports": 3,
    "audit_logs": 20,
    "chain_valid": 10,
    "chain_expired": 3,
    "chain_name_mismatch": 2,
    "chain_incomplete": 3,
    "expired": 12,
    "soon30": 8,
    "soon90": 10,
    "normal": 22,
}


def seed_all() -> dict[str, Any]:
    global CREATED, SKIPPED
    CREATED = 0
    SKIPPED = 0

    # 第一段事务：账号 / 端点 / 证书，提交后交给评估（评估自己开事务）
    with session_scope() as db:
        seed_users(db)
        endpoints = seed_endpoints(db)
        ca = build_ca_material()
        seed_certificates(db, endpoints, ca)
        db.flush()
    unparsable = seed_unparsable()

    outcome = assessment_service.run_assessment(run_id=None)
    print(
        "SEED_ASSESS certs={} chains={} valid={} expired={} mismatch={} incomplete={} avg={}".format(
            outcome.cert_total,
            outcome.chain_total,
            outcome.chain_valid,
            outcome.chain_expired,
            outcome.chain_name_mismatch,
            outcome.chain_incomplete,
            outcome.avg_score,
        ),
        flush=True,
    )

    # 第二段事务：迁移清单 / 导出记录 / 审计日志
    with session_scope() as db:
        certs = {cert.cert_key: cert for cert in db.query(CertificateAsset).all()}
        users = {user.role: user for user in db.query(User).all()}
        seed_migration(db, certs)
        seed_exports(db, users)
        seed_audit(db, users)
        db.flush()
        counts = summary_counts(db)
        counts["unparsable_pem"] = unparsable
        for key, expected in EXPECTED.items():
            if counts.get(key) != expected:
                print(
                    f"SEED_WARN key={key} expected={expected} actual={counts.get(key)}",
                    flush=True,
                )
        print("SEED_SUMMARY " + json.dumps(counts, sort_keys=True, ensure_ascii=False), flush=True)
        return {"created": CREATED, "skipped": SKIPPED, "counts": counts}


if __name__ == "__main__":
    result = seed_all()
    print(f"SEED_DONE created={result['created']} skipped={result['skipped']}", flush=True)
    sys.exit(0)
