import uuid
from datetime import datetime

from pydantic import BaseModel, Field, model_validator

from app.models.deployment import DeploymentSource
from app.models.inventory import Environment


class DeploymentCreate(BaseModel):
    """Either ids (from the UI) or names (from a pipeline, which knows its app name and
    release label but not our UUIDs). A version label that does not exist yet is created,
    since a deploy can be recorded before the SBOM for it has been synced."""

    application_id: uuid.UUID | None = None
    application_name: str | None = Field(default=None, max_length=255)
    app_version_id: uuid.UUID | None = None
    version_label: str | None = Field(default=None, max_length=255)
    environment: Environment
    image_digest: str | None = Field(default=None, max_length=255)
    reference_url: str | None = Field(default=None, max_length=1024)
    deployed_at: datetime | None = None

    @model_validator(mode="after")
    def _require_targets(self) -> "DeploymentCreate":
        if not self.application_id and not self.application_name:
            raise ValueError("application_id or application_name is required")
        if not self.app_version_id and not self.version_label:
            raise ValueError("app_version_id or version_label is required")
        return self


class DeploymentOut(BaseModel):
    id: uuid.UUID
    application_id: uuid.UUID
    application_name: str
    app_version_id: uuid.UUID
    version_label: str
    environment: Environment
    deployed_at: datetime
    ended_at: datetime | None
    image_digest: str | None
    reference_url: str | None
    source: DeploymentSource
    recorded_by: str
