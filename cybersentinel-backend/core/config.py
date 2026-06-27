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
    API_KEY: str = ""

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

    # Supabase (PostgreSQL) is the primary deployment database per FYP docs.
    # Set DATABASE_URL in .env to your Supabase connection string.
    # SQLite fallback allows offline local development without cloud DB.
    DATABASE_URL: str = f"sqlite+aiosqlite:///{BASE_DIR / 'cybersentinel.db'}"

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def normalize_database_url(cls, value: str) -> str:
        """Resolve SQLite paths and convert Supabase postgres:// URLs for asyncpg."""
        if not isinstance(value, str):
            return value

        # Supabase dashboard often gives postgresql:// — ensure async driver.
        if value.startswith("postgresql://"):
            value = "postgresql+asyncpg://" + value.removeprefix("postgresql://")
        elif value.startswith("postgres://"):
            value = "postgresql+asyncpg://" + value.removeprefix("postgres://")

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

    @property
    def database_provider(self) -> str:
        if self.DATABASE_URL.startswith("sqlite"):
            return "sqlite"
        if "supabase" in self.DATABASE_URL.lower():
            return "supabase"
        if self.DATABASE_URL.startswith("postgresql"):
            return "postgresql"
        return "unknown"

    @property
    def is_supabase(self) -> bool:
        return self.database_provider == "supabase"

    @property
    def uses_cloud_postgres(self) -> bool:
        return self.database_provider in {"supabase", "postgresql"}

    # ------------------------------------------------------------------
    # JWT Authentication (Sprint 3)
    # ------------------------------------------------------------------
    JWT_SECRET_KEY: str = "change-me-in-production-use-openssl-rand-hex-32"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 30
    DEFAULT_ADMIN_EMAIL: str = "admin@cybersentinel.local"
    DEFAULT_ADMIN_USERNAME: str = ""  # legacy env; mapped to email when set
    DEFAULT_ADMIN_PASSWORD: str = "admin123"
    ALLOW_PUBLIC_SIGNUP: bool = True
    USE_API_KEY_AUTH: bool = False

    # ------------------------------------------------------------------
    # Email (password reset)
    # ------------------------------------------------------------------
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""
    SMTP_FROM_NAME: str = "CyberSentinel"
    SMTP_USE_TLS: bool = True
    FRONTEND_RESET_PASSWORD_URL: str = "http://localhost:8080/reset-password"
    RESEND_API_KEY: str = ""

    @property
    def resend_configured(self) -> bool:
        return bool(self.RESEND_API_KEY.strip() and self.SMTP_FROM_EMAIL.strip())

    @property
    def smtp_configured(self) -> bool:
        return bool(self.SMTP_HOST.strip() and self.SMTP_FROM_EMAIL.strip())

    @property
    def email_configured(self) -> bool:
        return self.resend_configured or self.smtp_configured

    @property
    def email_provider(self) -> str:
        if self.resend_configured:
            return "resend"
        if self.smtp_configured:
            return "smtp"
        return "none"

    @property
    def default_admin_email(self) -> str:
        """Resolve admin email from DEFAULT_ADMIN_EMAIL or legacy DEFAULT_ADMIN_USERNAME."""
        email = self.DEFAULT_ADMIN_EMAIL.strip()
        if email and email != "admin@cybersentinel.local":
            return email.lower()
        legacy = self.DEFAULT_ADMIN_USERNAME.strip()
        if legacy:
            return legacy.lower() if "@" in legacy else f"{legacy.lower()}@cybersentinel.local"
        return email.lower()

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
    MAX_PCAP_PACKETS: int = 5000
    DASHBOARD_TREND_DAYS: int = 7
    COPILOT_LLM_API_KEY: str = ""
    COPILOT_LLM_BASE_URL: str = ""
    COPILOT_LLM_MODEL: str = ""
    CYBERSENTINEL_MASTER_KEY: str = ""
    SECRETS_ENC_PATH: Path = BASE_DIR / "secrets.enc"

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    # ------------------------------------------------------------------
    # Derived helpers — used by other modules so they don't hardcode paths
    # ------------------------------------------------------------------

    @property
    def supervised_bundle_path(self) -> Path:
        """Full path to the default random_forest supervised model bundle."""
        return self.SUPERVISED_MODEL_DIR / "packet_classifier_pipeline.joblib"

    def supervised_bundle_path_for(self, model_type: str) -> Path:
        return self.SUPERVISED_MODEL_DIR / f"packet_classifier_pipeline.{model_type}.joblib"

    @property
    def anomaly_model_path(self) -> Path:
        return self.UNSUPERVISED_MODEL_DIR / "anomaly_model.joblib"

    @property
    def packet_anomaly_model_path(self) -> Path:
        return self.SUPERVISED_MODEL_DIR / "packet_anomaly_isolation_forest.joblib"

    @property
    def clustering_model_path(self) -> Path:
        return self.UNSUPERVISED_MODEL_DIR / "clustering_model.joblib"

    def clustering_model_path_for(self, algorithm: str) -> Path:
        return self.UNSUPERVISED_MODEL_DIR / f"clustering_model.{algorithm}.joblib"

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
    instance = Settings()
    from core.secrets import load_secrets_into_settings

    load_secrets_into_settings(instance)
    return instance


# Convenience alias — most files just do: from core.config import settings
settings: Settings = get_settings()
