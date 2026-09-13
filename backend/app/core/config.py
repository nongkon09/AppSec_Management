from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration, loaded from environment variables / .env file.

    Every deployment-specific value must be settable through the environment, because
    Requirement.md Section 11.1 requires the same container image to run unchanged on
    Docker Compose/Swarm, Kubernetes/OpenShift and managed Kubernetes.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "local"
    secret_key: str = "insecure-dev-secret-change-me"
    access_token_expire_minutes: int = 480

    # Origins allowed to call the API from a browser. The default covers the local dev
    # frontend; real deployments set CORS_ALLOWED_ORIGINS to their dashboard hostname.
    cors_allowed_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        """Accept a comma-separated string, which is how the value arrives from a
        Compose file, Helm value or ConfigMap."""
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    database_url: str = "postgresql+psycopg://appsec:appsec@localhost:5432/appsec"

    dependency_track_base_url: str = "http://localhost:8081"
    dependency_track_api_key: str = ""

    # FR-2.4: Application flagged "Stale/ไม่ Sync" after this many days without a new SBOM.
    stale_sbom_days: int = 90

    # FR-3.1: background pull-sync from the SCA platform, at least 1-2x/day.
    # Off by default so importing app.main (e.g. in tests) never starts a background
    # job; real deployments opt in via ENABLE_SCHEDULER=true.
    enable_scheduler: bool = False
    sbom_sync_interval_hours: int = 6
    stale_check_interval_hours: int = 24
    # FR-6.2: how often the Waiver auto-expiry sweep runs.
    waiver_expiry_check_interval_hours: int = 24

    # FR-6.5: local disk directory for Pentest report file uploads (PDF/DOCX).
    pentest_report_upload_dir: str = "uploads/pentest-reports"


@lru_cache
def get_settings() -> Settings:
    return Settings()
