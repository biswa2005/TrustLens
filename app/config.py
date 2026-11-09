"""Central configuration for ThreatLens.

All runtime behaviour is controlled through environment variables (or a .env
file).  The application never *requires* a Hugging Face token: when one is not
configured it falls back to a clearly-labelled deterministic expert-system mode
so that every endpoint remains usable for development and offline forensics.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------ app
    app_name: str = "ThreatLens"
    app_version: str = "1.0.0"
    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    api_prefix: str = "/api/v1"
    cors_origins: str = "*"
    max_upload_mb: int = 12
    report_cache_size: int = 500

    # ------------------------------------------------------- Hugging Face
    hf_token: SecretStr | None = None
    hf_base_url: str = "https://router.huggingface.co/v1"
    text_model: str = "Qwen/Qwen2.5-72B-Instruct"
    fast_text_model: str = "Qwen/Qwen2.5-7B-Instruct"
    vision_model: str = "Qwen/Qwen2.5-VL-72B-Instruct"
    llm_mode: Literal["auto", "huggingface", "offline"] = "auto"
    llm_temperature: float = 0.1
    llm_max_tokens: int = 2000
    llm_timeout_seconds: float = 90.0
    llm_max_tool_steps: int = 3
    llm_retries: int = 2

    # ------------------------------------------------------- investigation
    allow_network: bool = True
    network_timeout_seconds: float = 8.0
    max_redirects: int = 4
    max_urls_per_investigation: int = 6
    max_email_bytes: int = 8 * 1024 * 1024
    max_image_pixels: int = 40_000_000
    enable_page_fetch: bool = True
    user_agent: str = (
        "ThreatLens/1.0 (+defensive-security-analysis; contact=security@example.invalid)"
    )

    # ---------------------------------------------------- threat intelligence
    google_safe_browsing_api_key: SecretStr | None = None
    virustotal_api_key: SecretStr | None = None
    urlscan_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    phishtank_api_key: SecretStr | None = None
    threat_intel_timeout_seconds: float = 7.0
    threat_intel_cache_ttl: int = 3600

    # ---------------------------------------------------------------- paths
    brand_registry_path: Path = BASE_DIR / "data" / "brands.json"
    brand_assets_dir: Path = BASE_DIR / "assets" / "brands"

    # --------------------------------------------------------------- crypto
    # Used to HMAC the evidence hash-chain.  A random per-process key is used
    # when unset; set it explicitly if reports must stay verifiable after a
    # restart.
    evidence_signing_key: SecretStr | None = None

    @field_validator("log_level")
    @classmethod
    def _upper_log_level(cls, value: str) -> str:
        level = value.upper()
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if level not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}")
        return level

    @property
    def hf_enabled(self) -> bool:
        return self.llm_mode != "offline" and bool(
            self.hf_token and self.hf_token.get_secret_value().strip()
        )

    @property
    def signing_key(self) -> bytes:
        if self.evidence_signing_key:
            return self.evidence_signing_key.get_secret_value().encode()
        # Stable for the lifetime of the process; persisted reports are not
        # intended to be long-term signed artefacts unless a key is supplied.
        if not hasattr(self, "_ephemeral_signing_key"):
            object.__setattr__(self, "_ephemeral_signing_key", secrets.token_bytes(32))
        return self._ephemeral_signing_key

    @property
    def cors_origin_list(self) -> list[str]:
        if self.cors_origins.strip() == "*":
            return ["*"]
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    def threat_intel_configured(self) -> dict[str, bool]:
        return {
            "google_safe_browsing": bool(self.google_safe_browsing_api_key),
            "virustotal": bool(self.virustotal_api_key),
            "urlscan": bool(self.urlscan_api_key),
            "abuseipdb": bool(self.abuseipdb_api_key),
            "phishtank": bool(self.phishtank_api_key),
            "urlhaus": self.allow_network,
            "rdap": self.allow_network,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Used by tests that mutate the environment between cases."""
    get_settings.cache_clear()
