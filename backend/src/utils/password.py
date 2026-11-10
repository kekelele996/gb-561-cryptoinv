"""口令散列：PBKDF2-HMAC-SHA256（210000 轮 + 16 字节随机盐，标准库实现）。

密码学项目里不引入额外 C 扩展依赖，格式 `pbkdf2_sha256$<rounds>$<salt_hex>$<hash_hex>`。
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

_ALGORITHM = "pbkdf2_sha256"
_ROUNDS = 210_000
_SALT_BYTES = 16


def hash_password(raw: str) -> str:
    salt = secrets.token_hex(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", raw.encode("utf-8"), salt.encode("ascii"), _ROUNDS).hex()
    return f"{_ALGORITHM}${_ROUNDS}${salt}${digest}"


def verify_password(raw: str, hashed: str) -> bool:
    try:
        algorithm, rounds, salt, digest = hashed.split("$", 3)
    except ValueError:
        return False
    if algorithm != _ALGORITHM:
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", raw.encode("utf-8"), salt.encode("ascii"), int(rounds)
    ).hex()
    return hmac.compare_digest(candidate, digest)
