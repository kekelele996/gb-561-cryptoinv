"""集中配置：全部来自环境变量，默认值与 .env.example 保持一致。"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    # 数据库
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "cryptoinv"
    db_user: str = "cryptoinv"
    db_password: str = "cryptoinv_pw_2026"

    # 安全
    jwt_secret: str = "cryptoinv-jwt-secret-change-me-2026"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 120
    refresh_token_days: int = 7

    # 运行时
    redis_url: str = "redis://localhost:6379/0"
    seed_demo: bool = True
    rate_limit_default_per_minute: int = 240
    rate_limit_assess_per_minute: int = 6

    # 证书 fixtures 目录（真实 PEM 样本，随镜像构建进入容器）
    cert_fixtures_dir: str = str(BASE_DIR / "fixtures" / "certs")

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
