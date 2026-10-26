"""Runtime settings loaded from the environment and an optional .env file."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

_REPO_ROOT = Path(__file__).resolve().parents[2]
_BACKEND_ROOT = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(str(_REPO_ROOT / ".env"), str(_BACKEND_ROOT / ".env"), ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    dev_mode: bool = False
    log_level: str = ""
    api_key: str = ""
    # Comma-separated additional keys (per-user tokens). Combined with api_key.
    api_keys: str = ""
    # Optional newline-delimited key file (one token per line). Useful on Cloud Run with a mounted secret.
    api_keys_file: str = ""
    # Firebase project id + secret used to mint/verify mg1.<uid>.<hmac> user tokens (no DB).
    firebase_project_id: str = ""
    account_token_secret: str = ""
    request_signing_secret: str = ""
    signature_max_age_seconds: int = 300
    max_request_bytes: int = 12 * 1024 * 1024
    rate_limit_per_minute: int = 30

    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-5"
    llm_mode: Literal["redacted", "evidence_only", "off"] = "redacted"
    llm_skip_senders: str = ""

    urlhaus_auth_key: str = ""
    phishtank_api_key: str = ""
    safe_browsing_api_key: str = ""
    enable_live_dns: bool = False
    enable_whois: bool = True
    use_transformers: bool = False
    transformer_model: str = "ealvaradob/bert-finetuned-phishing"
    new_domain_days: int = 30
    young_domain_days: int = 90

    inspect_isolation: bool = True
    inspect_timeout_seconds: float = 8.0

    @property
    def effective_log_level(self) -> str:
        return (self.log_level or ("INFO" if self.dev_mode else "WARNING")).upper()

    @property
    def skip_senders(self) -> frozenset[str]:
        return frozenset(item.strip().lower() for item in self.llm_skip_senders.split(",") if item.strip())

    def startup_problems(self) -> list[str]:
        """Return configuration errors that must block a non-dev server from starting."""
        if self.dev_mode:
            return []
        problems = []
        has_shared = len(self.api_key) >= 24
        has_user_tokens = len(self.account_token_secret) >= 32
        if not has_shared and not has_user_tokens:
            problems.append(
                "Set API_KEY (24+ chars) and/or ACCOUNT_TOKEN_SECRET (32+ chars) for request auth."
            )
        if len(self.request_signing_secret) < 32:
            problems.append("REQUEST_SIGNING_SECRET must be set to a random value of at least 32 characters.")
        return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()
