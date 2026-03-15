"""
Application configuration.

All values are loaded from environment variables (and .env when present).
No defaults for secrets — the app will fail to start if they are absent.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ───────────────────────────────────────────────────────────
    app_name: str = "llmx-backend"
    app_version: str = "0.1.0"
    app_env: str = Field(default="development", pattern=r"^(development|staging|production)$")
    debug: bool = False

    # ── Logging ───────────────────────────────────────────────────────────────
    log_level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    log_format: str = Field(default="json", pattern=r"^(json|pretty)$")

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str  # required — no default
    db_pool_size: int = 10
    db_max_overflow: int = 20

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Security ──────────────────────────────────────────────────────────────
    ingestion_api_key: str  # required — no default

    # ── Ingestion limits ──────────────────────────────────────────────────────
    max_html_size_bytes: int = 5 * 1024 * 1024   # 5 MB
    max_selected_text_bytes: int = 64 * 1024      # 64 KB

    @model_validator(mode="after")
    def _validate_secrets(self) -> Settings:
        if self.app_env == "production":
            if len(self.ingestion_api_key) < 32:
                raise ValueError(
                    "ingestion_api_key must be at least 32 characters in production"
                )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
