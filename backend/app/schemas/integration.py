import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.finding import SeverityTier
from app.models.integration import ConnectorType


class ConnectorCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    connector_type: ConnectorType
    base_url: str = Field(min_length=1, max_length=1024)
    auth_token: str = Field(min_length=1, max_length=1024)
    config: dict = Field(default_factory=dict)
    # FR-7.2: severities auto-routed here; empty = manual-only (FR-7.8).
    routing_severities: list[SeverityTier] = Field(default_factory=list)
    is_enabled: bool = True


class ConnectorUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    base_url: str | None = Field(default=None, min_length=1, max_length=1024)
    # Omitted (not just empty-string) means "leave the stored token unchanged" — the
    # token is never round-tripped back to the client, so there is nothing to compare
    # against to detect "no change" the way other fields would.
    auth_token: str | None = Field(default=None, min_length=1, max_length=1024)
    config: dict | None = None
    routing_severities: list[SeverityTier] | None = None
    is_enabled: bool | None = None


class ConnectorOut(BaseModel):
    id: uuid.UUID
    name: str
    connector_type: ConnectorType
    base_url: str
    config: dict
    routing_severities: list[SeverityTier]
    is_enabled: bool
    created_at: datetime
    # FR-7's security note: the credential itself is never returned once stored.
    auth_token_configured: bool = True

    model_config = {"from_attributes": True}


class TicketOut(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    connector_id: uuid.UUID | None
    external_system: str
    external_id: str
    status: str
    last_error: str | None
    last_synced_at: datetime | None
    retry_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


class ManualTicketCreate(BaseModel):
    connector_id: uuid.UUID
