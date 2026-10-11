"""Runtime configuration.

All settings come from environment variables (prefix ``TERMINUS_``) or a local,
git-ignored ``.env`` file. Secret values are typed as ``SecretStr`` so they are
never rendered by ``repr()``, logging, or Pydantic serialization.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_VENDOR_DOMAINS = (
    "openssl.org",
    "openssl-library.org",
    "httpd.apache.org",
    "logging.apache.org",
    "tomcat.apache.org",
    "curl.se",
    "nginx.org",
    "openssh.com",
    "www.openssh.com",
    "github.com",
    "msrc.microsoft.com",
    "access.redhat.com",
    "security-tracker.debian.org",
    "ubuntu.com",
    "www.djangoproject.com",
    "nodejs.org",
    "www.postgresql.org",
    "kb.cert.org",
    "www.kb.cert.org",
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TERMINUS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- general -----------------------------------------------------------
    mode: Literal["live", "demo"] = "live"
    db_path: Path = PROJECT_ROOT / "terminus.db"
    log_level: str = "INFO"

    # --- API protection ----------------------------------------------------
    # State-changing API endpoints are disabled unless a token is configured.
    api_token: SecretStr | None = None

    # --- data sources ------------------------------------------------------
    nvd_api_key: SecretStr | None = None
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_results_per_page: int = Field(default=500, ge=1, le=2000)
    nvd_max_pages: int = Field(default=20, ge=1, le=500)
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    epss_base_url: str = "https://api.first.org/data/v1/epss"
    osv_base_url: str = "https://api.osv.dev/v1"
    incremental_window_days: int = Field(default=7, ge=1, le=120)

    # --- HTTP hardening ------------------------------------------------------
    http_timeout_seconds: float = Field(default=20.0, gt=0, le=120)
    http_max_retries: int = Field(default=3, ge=0, le=6)
    http_backoff_base_seconds: float = Field(default=1.0, ge=0, le=30)
    http_max_response_bytes: int = Field(default=40_000_000, ge=10_000)
    vendor_page_max_bytes: int = Field(default=1_500_000, ge=10_000)
    cache_ttl_hours: float = Field(default=12.0, ge=0)

    # --- vendor advisory fetching -----------------------------------------
    fetch_vendor_pages: bool = True
    vendor_domain_allowlist: tuple[str, ...] = DEFAULT_VENDOR_DOMAINS

    # --- optional web research --------------------------------------------
    search_provider: Literal["none", "tavily", "exa"] = "none"
    tavily_api_key: SecretStr | None = None
    exa_api_key: SecretStr | None = None

    # --- optional LLM research layer --------------------------------------
    llm_provider: Literal["none", "openai", "anthropic"] = "none"
    llm_model: str | None = None
    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None

    # --- research agent budgets -------------------------------------------
    agent_max_tool_calls: int = Field(default=12, ge=1, le=50)
    agent_max_search_calls: int = Field(default=2, ge=0, le=10)
    agent_max_seconds: float = Field(default=60.0, gt=0, le=600)
    agent_max_findings_per_scan: int = Field(default=200, ge=1, le=5000)

    @property
    def is_demo(self) -> bool:
        return self.mode == "demo"

    def configured_secret_names(self) -> list[str]:
        """Names (never values) of secrets that are set. Safe to display."""
        names = []
        for name in (
            "api_token",
            "nvd_api_key",
            "tavily_api_key",
            "exa_api_key",
            "openai_api_key",
            "anthropic_api_key",
        ):
            value = getattr(self, name)
            if value is not None and value.get_secret_value():
                names.append(f"TERMINUS_{name.upper()}")
        return names


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
