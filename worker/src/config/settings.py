"""worker 侧配置：与 backend 共用同名环境变量，不重复定义业务口径。"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class WorkerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "cryptoinv"
    db_user: str = "cryptoinv"
    db_password: str = "cryptoinv_pw_2026"
    redis_url: str = "redis://localhost:6379/0"

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )


@lru_cache
def get_settings() -> WorkerSettings:
    return WorkerSettings()


settings = get_settings()
