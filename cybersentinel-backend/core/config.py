"""
core/config.py

Central configuration for CyberSentinel backend.
All settings are read from environment variables or a .env file.
Nothing is hardcoded — API keys, paths, and thresholds all live here.

Usage:
    from core.config import settings
    print(settings.APP_NAME)
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated, List

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


# ---------------------------------------------------------------------------
# Base directory — everything is relative to the backend root
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """
    All configuration values for CyberSentinel.

    Values are loaded in this priority order:
      1. Environment variables
      2. .env file in the project root
      3. Defaults defined below

    Never commit a real .env file to version control.
    """

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",          # silently ignore unknown env vars
    )

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------
    APP_NAME: str = "CyberSentinel"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ADMIN_API_KEY: str = ""

    @field_validator("DEBUG", mode="before")
    @classmethod
    def parse_debug(cls, value: object) -> object:
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"release", "prod", "production"}:
                return False
            if normalized in {"dev", "development"}:
                return True
        return value

    # ------------------------------------------------------------------
    # Server
    # ------------------------------------------------------------------
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # ------------------------------------------------------------------
    # CORS — Flutter web origin(s).
    # In production replace "*" with your actual Flutter web domain.
    # ------------------------------------------------------------------
    CORS_ORIGINS: Annotated[List[str], NoDecode] = Field(
        default=["http://localhost", "http://localhost:3000", "http://localhost:8080"],
    )
    CORS_ALLOW_CREDENTIALS: bool = False

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors(cls, value: str | List[str]) -> List[str]:
        """Accept a comma-separated string or a list from the environment."""
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    # ------------------------------------------------------------------
    # Database
    # SQLite by default so the project runs without a database server.
    # Switch to postgresql+asyncpg://... for production.
    # ------------------------------------------------------------------
    DATABASE_URL: str = f"sqlite+aiosqlite:///{BASE_DIR / 'cybersentinel.db'}"

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def resolve_sqlite_url(cls, value: str) -> str:
        """Resolve relative SQLite database paths against the backend root."""
        if not isinstance(value, str):
            return value

        prefixes = ("sqlite+aiosqlite:///", "sqlite:///")
        for prefix in prefixes:
            if value.startswith(prefix) and not value.startswith(prefix + "/"):
                raw_path = value.removeprefix(prefix)
                if raw_path and raw_path != ":memory:":
                    db_path = Path(raw_path)
                    if not db_path.is_absolute():
                        db_path = BASE_DIR / db_path
                    return f"{prefix}{db_path.resolve()}"
        return value

    # ------------------------------------------------------------------
    # ML model paths
    # These point to the .pkl / .joblib files your training scripts saved.
    # ------------------------------------------------------------------

    # Supervised — packet classifier (CyberSentinelPacketClassifier bundle)
    SUPERVISED_MODEL_DIR: Path = BASE_DIR.parent / "supervised_learning" / "models"

    # Unsupervised — firewall anomaly + clustering
    UNSUPERVISED_MODEL_DIR: Path = BASE_DIR.parent / "unsupervised_learning" / "models"

    @field_validator("SUPERVISED_MODEL_DIR", "UNSUPERVISED_MODEL_DIR", mode="before")
    @classmethod
    def resolve_path(cls, value: str | Path) -> Path:
        path = Path(value)
        if not path.is_absolute():
            path = BASE_DIR / path
        return path.resolve()

    # ------------------------------------------------------------------
    # External API keys
    # These default to empty strings so the app starts without them.
    # Endpoints that need them will return a 503 if not configured.
    # ------------------------------------------------------------------
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    # GeoIP — free tier: https://ip-api.com (no key needed for basic use)
    # Set to a paid provider URL if you need higher rate limits.
    GEOIP_BASE_URL: str = "http://ip-api.com/json"

    # ------------------------------------------------------------------
    # API rate limiting (requests per minute per client IP)
    # ------------------------------------------------------------------
    RATE_LIMIT_PER_MINUTE: int = 60

    # ------------------------------------------------------------------
    # Threat scoring weights for future cross-signal risk aggregation.
    # ------------------------------------------------------------------
    ENSEMBLE_WEIGHT_PACKET: float = 0.30
    ENSEMBLE_WEIGHT_ANOMALY: float = 0.35
    ENSEMBLE_WEIGHT_VIRUSTOTAL: float = 0.20
    ENSEMBLE_WEIGHT_IP_REPUTATION: float = 0.15
    RESPONSE_ACTION_EXECUTION_ENABLED: bool = False

    @field_validator(
        "ENSEMBLE_WEIGHT_PACKET",
        "ENSEMBLE_WEIGHT_ANOMALY",
        "ENSEMBLE_WEIGHT_VIRUSTOTAL",
        "ENSEMBLE_WEIGHT_IP_REPUTATION",
        mode="after",
    )
    @classmethod
    def weights_in_range(cls, value: float) -> float:
        if not (0.0 <= value <= 1.0):
            raise ValueError("Ensemble weights must be between 0.0 and 1.0")
        return value

    # ------------------------------------------------------------------
    # Pagination defaults
    # ------------------------------------------------------------------
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 500

    # ------------------------------------------------------------------
    # File upload limits
    # ------------------------------------------------------------------
    MAX_UPLOAD_SIZE_MB: int = 50  # for CSV / log file uploads
    MAX_BATCH_FLOWS: int = 10_000

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    # ------------------------------------------------------------------
    # Derived helpers — used by other modules so they don't hardcode paths
    # ------------------------------------------------------------------

    @property
    def supervised_bundle_path(self) -> Path:
        """Full path to the unified supervised model bundle."""
        return self.SUPERVISED_MODEL_DIR / "packet_classifier_pipeline.joblib"

    @property
    def anomaly_model_path(self) -> Path:
        return self.UNSUPERVISED_MODEL_DIR / "anomaly_model.joblib"

    @property
    def clustering_model_path(self) -> Path:
        return self.UNSUPERVISED_MODEL_DIR / "clustering_model.joblib"

    @property
    def virustotal_configured(self) -> bool:
        return bool(self.VIRUSTOTAL_API_KEY)

    @property
    def abuseipdb_configured(self) -> bool:
        return bool(self.ABUSEIPDB_API_KEY)

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        weights = (
            self.ENSEMBLE_WEIGHT_PACKET
            + self.ENSEMBLE_WEIGHT_ANOMALY
            + self.ENSEMBLE_WEIGHT_VIRUSTOTAL
            + self.ENSEMBLE_WEIGHT_IP_REPUTATION
        )
        if abs(weights - 1.0) > 1e-9:
            raise ValueError("Ensemble weights must sum to 1.0")

        if "*" in self.CORS_ORIGINS and self.CORS_ALLOW_CREDENTIALS:
            raise ValueError("CORS_ALLOW_CREDENTIALS cannot be true when CORS_ORIGINS contains '*'")

        if self.RATE_LIMIT_PER_MINUTE < 1:
            raise ValueError("RATE_LIMIT_PER_MINUTE must be at least 1")

        if self.MAX_UPLOAD_SIZE_MB < 1:
            raise ValueError("MAX_UPLOAD_SIZE_MB must be at least 1")

        if self.MAX_BATCH_FLOWS < 1:
            raise ValueError("MAX_BATCH_FLOWS must be at least 1")

        return self


# ---------------------------------------------------------------------------
# Singleton — import `settings` everywhere instead of instantiating Settings()
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Returns a cached Settings instance.
    Using lru_cache means .env is only read once at startup.
    Call get_settings.cache_clear() in tests to reload.
    """
    return Settings()


# Convenience alias — most files just do: from core.config import settings
settings: Settings = get_settings()
