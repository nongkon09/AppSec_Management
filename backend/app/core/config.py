from functools import lru_cache
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


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
    #
    # `NoDecode` is required: pydantic-settings treats `list[str]` as a "complex" type
    # and, for an env-sourced value, tries to `json.loads()` it *before* any validator
    # runs — a plain comma-separated string ("a,b") is not valid JSON, so without this
    # it raises `SettingsError` at Settings() construction time whenever the variable
    # is actually set (verified: this broke unnoticed because the one long-running dev
    # container that appeared to work pre-dates this env var being added to Compose,
    # so it was only ever exercising the Python-literal default, never the env path).
    cors_allowed_origins: Annotated[list[str], NoDecode] = [
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

    # Where users open the dashboard, and where their browser reaches the API. Behind the
    # production nginx both are APP_PUBLIC_URL; in local dev the API is its own port.
    # Used to build the Entra ID redirect URI and to send the browser back after sign-in.
    app_public_url: str = "http://localhost:5173"
    api_public_url: str = ""

    # Entra ID sign-in (OIDC authorization code + PKCE, docs/entra-id.md). Sign-in with
    # Microsoft is offered only when all three are set.
    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: str = ""
    entra_authority_host: str = "https://login.microsoftonline.com"
    # Create an account on first sign-in when a role mapping matches, without waiting
    # for SCIM. Turn off to admit only accounts SCIM has provisioned.
    entra_jit_provisioning: bool = True
    # SCIM 2.0 provisioning from Entra ID: the secret token entered in the enterprise
    # app's Provisioning page. Empty disables the SCIM endpoints.
    scim_bearer_token: str = ""
    # False: once everyone signs in with Microsoft, only local System Admin (break-glass)
    # and the CI/CD service account may still use a password.
    local_login_enabled: bool = True

    dependency_track_base_url: str = "http://localhost:8081"
    # FR-2.7.4: the sync key is read-only (VIEW_PORTFOLIO + VIEW_VULNERABILITY). Forwarding a
    # manual/COTS SBOM (FR-2.6.1) needs BOM_UPLOAD + PROJECT_CREATION_UPLOAD, so it uses a
    # separate key; leave it empty to keep manual uploads local-only.
    dependency_track_api_key: str = ""
    dependency_track_upload_api_key: str = ""

    # FR-4.1 exploitation signals, fetched during pull-sync when the SCA platform does not
    # supply them. Empty string disables the lookup (tests, air-gapped deployments).
    cisa_kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    osv_api_url: str = "https://api.osv.dev/v1/vulns"

    # FR-2.4: Application flagged "Stale/ไม่ Sync" after this many days without a new SBOM.
    stale_sbom_days: int = 90

    # FR-3.1: background pull-sync from the SCA platform, at least 1-2x/day.
    # Off by default so importing app.main (e.g. in tests) never starts a background
    # job; real deployments opt in via ENABLE_SCHEDULER=true.
    enable_scheduler: bool = False
    sbom_sync_interval_hours: int = 6
    stale_check_interval_hours: int = 24
    # How often exceptions are expired, closed or flagged for review.
    exception_sweep_interval_hours: int = 24

    # FR-6.5: local disk directory for Pentest report file uploads (PDF/DOCX).
    pentest_report_upload_dir: str = "uploads/pentest-reports"
    # Scan evidence: SBOM files kept alongside each scan snapshot.
    sbom_evidence_dir: str = "uploads/sbom-evidence"

    @property
    def entra_enabled(self) -> bool:
        return bool(self.entra_tenant_id and self.entra_client_id and self.entra_client_secret)

    @property
    def scim_enabled(self) -> bool:
        return bool(self.scim_bearer_token)

    @property
    def api_base_url(self) -> str:
        """The API as the browser reaches it, e.g. https://appsec.example.org/api/v1."""
        return (self.api_public_url or self.app_public_url).rstrip("/") + "/api/v1"


@lru_cache
def get_settings() -> Settings:
    return Settings()
