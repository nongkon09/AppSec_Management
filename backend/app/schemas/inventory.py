import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.inventory import AppType, Criticality, Environment


class ApplicationCreate(BaseModel):
    app_name: str
    app_type: AppType
    owner_team: str
    tech_lead_contact: str | None = None
    business_unit: str | None = None
    criticality: Criticality = Criticality.MEDIUM
    environment: Environment = Environment.PRODUCTION
    internet_facing: bool = False
    data_classification: str | None = None
    repo_url: str | None = None
    jira_project_key: str | None = None
    sdp_category: str | None = None
    owner_email: str | None = None


class ApplicationUpdate(BaseModel):
    app_name: str | None = None
    owner_team: str | None = None
    tech_lead_contact: str | None = None
    business_unit: str | None = None
    criticality: Criticality | None = None
    internet_facing: bool | None = None
    data_classification: str | None = None
    repo_url: str | None = None
    jira_project_key: str | None = None
    sdp_category: str | None = None
    owner_email: str | None = None


class ApplicationOut(BaseModel):
    id: uuid.UUID
    app_name: str
    app_type: AppType
    owner_team: str
    tech_lead_contact: str | None
    business_unit: str | None
    criticality: Criticality
    environment: Environment
    internet_facing: bool
    data_classification: str | None
    repo_url: str | None
    jira_project_key: str | None
    sdp_category: str | None
    owner_email: str | None
    ownership_confirmed: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class AppVersionCreate(BaseModel):
    version_label: str
    commit_sha: str | None = None
    environment: Environment = Environment.PRODUCTION
    is_current_production: bool = False


class AppVersionOut(BaseModel):
    id: uuid.UUID
    application_id: uuid.UUID
    version_label: str
    commit_sha: str | None
    environment: Environment
    is_current_production: bool
    last_ingested_at: datetime | None
    is_stale: bool
    is_active: bool

    model_config = {"from_attributes": True}


class PaginatedApplications(BaseModel):
    items: list[ApplicationOut]
    total: int = Field(ge=0)
