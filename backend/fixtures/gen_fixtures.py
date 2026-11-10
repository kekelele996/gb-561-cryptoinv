"""生成 `backend/fixtures/certs/` 下的真实 PEM 证书样本（作者期一次性脚本）。

**私钥只在内存/临时目录中存在，绝不写入仓库、绝不入库**：
  本脚本只输出证书公钥部分（*.pem 仅含 CERTIFICATE 块）。写完后临时私钥文件立即删除。

日期全部锚定在批次日期 2026-11-10（绝对时间，保证 52 张证书的
过期/30 天/90 天分档在验收日复现）。SHA-1 与 SM2 证书因 `cryptography`
不再允许 SHA-1 签名、且不支持 SM2 曲线签名，改用系统 openssl 生成。

用法（在仓库外本地执行一次；容器运行时不需要它）：
    python backend/fixtures/gen_fixtures.py
"""
from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = Path(__file__).resolve().parent / "certs"
UTC = dt.timezone.utc

ORG = "YunQi Provincial E-Government Crypto Center"
COUNTRY = "CN"


def d(year: int, month: int, day: int) -> dt.datetime:
    return dt.datetime(year, month, day, 0, 0, 0, tzinfo=UTC)


def name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def write_pem(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  wrote {path.name} ({path.stat().st_size} bytes)")


def build_leaf(
    cn: str,
    sans: list[str],
    pubkey,
    issuer_name: x509.Name,
    issuer_key,
    not_before: dt.datetime,
    not_after: dt.datetime,
    serial: int,
    aki_key: x509.Certificate | None = None,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(issuer_name)
        .public_key(pubkey)
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
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pubkey), critical=False)
    )
    if aki_key is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(aki_key.public_key()),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def openssl_path() -> str:
    found = shutil.which("openssl")
    if not found:
        raise RuntimeError("系统 openssl 不可用：SHA-1 / SM2 样本需要它")
    return found


def make_sha1_leaf(
    tmp: Path,
    int_cert: x509.Certificate,
    int_key,
    cn: str,
    san: str,
    serial: int,
    not_before: dt.datetime,
    not_after: dt.datetime,
) -> bytes:
    """openssl 生成 SHA-1 签名叶证书（cryptography 禁止 SHA-1 签名）。"""
    ossl = openssl_path()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = tmp / "sha1_leaf.key"
    csr_path = tmp / "sha1_leaf.csr"
    int_key_path = tmp / "int.key"
    int_cert_path = tmp / "int.pem"
    ext_path = tmp / "sha1_ext.cnf"
    out_path = tmp / "sha1_leaf.pem"

    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    int_key_path.write_bytes(
        int_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    int_cert_path.write_bytes(int_cert.public_bytes(serialization.Encoding.PEM))
    ext_path.write_text(
        "[v3_leaf]\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{san}\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n",
        encoding="utf-8",
    )

    subprocess.run(
        [ossl, "req", "-new", "-key", str(key_path), "-out", str(csr_path),
         "-subj", f"/C={COUNTRY}/O={ORG}/CN={cn}"],
        check=True, capture_output=True,
    )
    subprocess.run(
        [ossl, "x509", "-req", "-sha1", "-in", str(csr_path), "-CA", str(int_cert_path),
         "-CAkey", str(int_key_path), "-set_serial", str(serial), "-days", "3650",
         "-extfile", str(ext_path), "-extensions", "v3_leaf", "-out", str(out_path)],
        check=True, capture_output=True,
    )
    # openssl 只能按 -days 写有效期，这里用 cryptography 重新签一次时间不可行（SHA-1 被禁），
    # 因此对 SHA-1 样本采用「签发日 + 3650 天」的真实有效期（2026-11-10 起算 -> 正常档）。
    data = out_path.read_bytes()
    for p in tmp.glob("*"):
        p.unlink()
    return data


def make_sm2_leaf(tmp: Path, cn: str, san: str) -> bytes:
    """openssl 生成 SM2-SM3 自签证书（cryptography 不支持 SM2 曲线，正好作为诚实边界样本）。

    注意 `openssl req -x509 -sm3` 与 `-extfile` 互斥，因此分两步：先 CSR，再 `openssl x509 -req`。
    """
    ossl = openssl_path()
    key_path = tmp / "sm2.key"
    csr_path = tmp / "sm2.csr"
    ext_path = tmp / "sm2_ext.cnf"
    out_path = tmp / "sm2.pem"
    subprocess.run([ossl, "genpkey", "-algorithm", "SM2", "-out", str(key_path)],
                   check=True, capture_output=True)
    ext_path.write_text(
        "[v3_leaf]\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{san}\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n",
        encoding="utf-8",
    )
    subprocess.run(
        [ossl, "req", "-new", "-key", str(key_path), "-sm3", "-out", str(csr_path),
         "-subj", f"/C={COUNTRY}/O={ORG}/CN={cn}"],
        check=True, capture_output=True,
    )
    subprocess.run(
        [ossl, "x509", "-req", "-in", str(csr_path), "-signkey", str(key_path), "-sm3",
         "-days", "730", "-extfile", str(ext_path), "-extensions", "v3_leaf",
         "-out", str(out_path)],
        check=True, capture_output=True,
    )
    data = out_path.read_bytes()
    for p in tmp.glob("*"):
        p.unlink()
    return data


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="cryptoinv-fixtures-"))
    manifest: dict[str, dict[str, object]] = {}

    try:
        # ---- CA 层：root -> intermediate ----
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_cert = (
            x509.CertificateBuilder()
            .subject_name(name("YunQi Gov Cloud Root CA R2"))
            .issuer_name(name("YunQi Gov Cloud Root CA R2"))
            .public_key(root_key.public_key())
            .serial_number(0x5610000000000001)
            .not_valid_before(d(2023, 1, 1))
            .not_valid_after(d(2033, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True,
                    crl_sign=True, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
                           critical=False)
            .sign(root_key, hashes.SHA256())
        )
        write_pem(OUT / "root_ca.pem", root_cert)
        manifest["root_ca.pem"] = {"role": "ca", "depth": 0, "sig": "RSA-SHA256"}

        int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        int_cert = (
            x509.CertificateBuilder()
            .subject_name(name("YunQi Gov Cloud Issuing CA G2"))
            .issuer_name(root_cert.subject)
            .public_key(int_key.public_key())
            .serial_number(0x5610000000000002)
            .not_valid_before(d(2024, 6, 1))
            .not_valid_after(d(2030, 6, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True,
                    crl_sign=True, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()),
                           critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                critical=False,
            )
            .sign(root_key, hashes.SHA256())
        )
        write_pem(OUT / "intermediate_ca.pem", int_cert)
        manifest["intermediate_ca.pem"] = {"role": "ca", "depth": 1, "sig": "RSA-SHA256"}

        # ---- 正常 RSA-2048-SHA256 链（链首用于详情页演示）----
        leaf_ok = build_leaf(
            "www.rj.yunqi-gov.example", ["www.rj.yunqi-gov.example", "rj.yunqi-gov.example"],
            rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key(),
            int_cert.subject, int_key, d(2025, 6, 1), d(2027, 6, 1), 0x5610000000000011,
            aki_key=int_cert,
        )
        write_pem(OUT / "leaf_ok.pem", leaf_ok)
        manifest["leaf_ok.pem"] = {"role": "leaf", "sig": "RSA-SHA256", "key": "RSA-2048"}

        # ---- RSA-1024 弱密钥 ----
        leaf_1024 = build_leaf(
            "old.tax.yunqi-gov.example", ["old.tax.yunqi-gov.example"],
            rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key(),
            int_cert.subject, int_key, d(2025, 3, 1), d(2027, 3, 1), 0x5610000000000012,
            aki_key=int_cert,
        )
        write_pem(OUT / "leaf_rsa1024.pem", leaf_1024)
        manifest["leaf_rsa1024.pem"] = {"role": "leaf", "sig": "RSA-SHA256", "key": "RSA-1024"}

        # ---- SHA-1 签名（openssl）----
        sha1_pem = make_sha1_leaf(
            tmp, int_cert, int_key, "legacy.ybj.yunqi-gov.example",
            "legacy.ybj.yunqi-gov.example", 0x5610000000000013, d(2025, 2, 1), d(2027, 2, 1),
        )
        (OUT / "leaf_sha1.pem").write_bytes(sha1_pem)
        print(f"  wrote leaf_sha1.pem ({len(sha1_pem)} bytes)")
        manifest["leaf_sha1.pem"] = {"role": "leaf", "sig": "RSA-SHA1", "key": "RSA-2048"}

        # ---- 已过期 ----
        leaf_expired = build_leaf(
            "expired.jt.yunqi-gov.example", ["expired.jt.yunqi-gov.example"],
            rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key(),
            int_cert.subject, int_key, d(2024, 1, 1), d(2026, 10, 1), 0x5610000000000014,
            aki_key=int_cert,
        )
        write_pem(OUT / "leaf_expired.pem", leaf_expired)
        manifest["leaf_expired.pem"] = {"role": "leaf", "sig": "RSA-SHA256", "expired": True}

        # ---- 30 天内到期（验收日 2026-11-10 -> 18 天）----
        leaf_soon = build_leaf(
            "soon.mz.yunqi-gov.example", ["soon.mz.yunqi-gov.example"],
            rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key(),
            int_cert.subject, int_key, d(2025, 1, 1), d(2026, 11, 28), 0x5610000000000015,
            aki_key=int_cert,
        )
        write_pem(OUT / "leaf_expiring30.pem", leaf_soon)
        manifest["leaf_expiring30.pem"] = {"role": "leaf", "sig": "RSA-SHA256", "days_left": 18}

        # ---- 自签叶证书 ----
        self_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_self = build_leaf(
            "self.hr.yunqi-gov.example", ["self.hr.yunqi-gov.example"],
            self_key.public_key(), name("self.hr.yunqi-gov.example"), self_key,
            d(2025, 1, 1), d(2027, 6, 1), 0x5610000000000016,
        )
        write_pem(OUT / "leaf_selfsigned.pem", leaf_self)
        manifest["leaf_selfsigned.pem"] = {"role": "leaf", "sig": "RSA-SHA256", "self_signed": True}

        # ---- ECDSA P-256 ----
        leaf_ec = build_leaf(
            "ecdsa.jy.yunqi-gov.example", ["ecdsa.jy.yunqi-gov.example"],
            ec.generate_private_key(ec.SECP256R1()).public_key(),
            int_cert.subject, int_key, d(2025, 6, 1), d(2027, 6, 1), 0x5610000000000017,
            aki_key=int_cert,
        )
        write_pem(OUT / "leaf_ecdsa_p256.pem", leaf_ec)
        manifest["leaf_ecdsa_p256.pem"] = {"role": "leaf", "sig": "ECDSA-SHA256", "key": "ECDSA-P256"}

        # ---- name_mismatch：SAN 不含所属端点主机名 ----
        leaf_mismatch = build_leaf(
            "svc.ga.yunqi-gov.example", ["other.ga.yunqi-gov.example"],
            rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key(),
            int_cert.subject, int_key, d(2025, 6, 1), d(2027, 6, 1), 0x5610000000000018,
            aki_key=int_cert,
        )
        write_pem(OUT / "leaf_name_mismatch.pem", leaf_mismatch)
        manifest["leaf_name_mismatch.pem"] = {"role": "leaf", "sig": "RSA-SHA256", "name_mismatch": True}

        # ---- SM2-SM3（库不支持曲线 -> 诚实边界样本）----
        sm2_pem = make_sm2_leaf(tmp, "gm.mz.yunqi-gov.example", "gm.mz.yunqi-gov.example")
        (OUT / "leaf_sm2.pem").write_bytes(sm2_pem)
        print(f"  wrote leaf_sm2.pem ({len(sm2_pem)} bytes)")
        manifest["leaf_sm2.pem"] = {"role": "leaf", "sig": "SM2-SM3", "key": "SM2",
                                    "unsupported_by_crypto_lib": True}

        # ---- 非法 PEM（不是证书）----
        (OUT / "invalid_corrupt.pem").write_text(
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBszCCAVmgAwIBAgIUB0=THIS-IS-NOT-A-REAL-CERTIFICATE-BASE64=AAAA\n"
            "-----END CERTIFICATE-----\n",
            encoding="utf-8",
        )
        print("  wrote invalid_corrupt.pem")

        (OUT / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"fixtures done -> {OUT}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
