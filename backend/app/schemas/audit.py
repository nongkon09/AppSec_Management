import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AuditLogOut(BaseModel):
    id: uuid.UUID
    action: str
    actor: str
    entity_type: str
    entity_id: str
    before_value: dict[str, Any] | None
    after_value: dict[str, Any] | None
    timestamp: datetime

    model_config = {"from_attributes": True}


class PaginatedAuditLogs(BaseModel):
    items: list[AuditLogOut]
    total: int = Field(ge=0)
