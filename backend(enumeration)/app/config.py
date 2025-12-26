"""Application configuration using Pydantic Settings."""

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_name: str = "AETHER Scanner"
    app_version: str = "0.1.0"
    debug: bool = False

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # CORS
    cors_origins: List[str] = [
        "http://localhost:8080",
        "http://localhost:3000",
        "http://127.0.0.1:8080",
    ]

    # Database
    database_url: str = "postgresql+asyncpg://aether:aether@localhost:5432/aether"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Scanner Configuration
    scan_rate_limit_ms: int = 500  # Delay between requests in milliseconds
    scan_timeout_seconds: int = 30  # Timeout per request
    max_concurrent_scans: int = 5  # Maximum parallel scans
    max_crawl_depth: int = 3  # Maximum depth for crawling
    max_urls_per_scan: int = 100  # Maximum URLs to scan per job
    user_agent: str = "AETHER-Scanner/0.1.0 (Security Research)"

    # Authentication (for future use)
    secret_key: str = "change-me-in-production-use-strong-random-key"
    access_token_expire_minutes: int = 30


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
