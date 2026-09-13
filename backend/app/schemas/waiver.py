import uuid
from datetime import date, datetime

from pydantic import BaseModel, Field

from app.models.waiver import WaiverStatus


class WaiverCreate(BaseModel):
    """FR-6.2: Dev/Tech Lead (or AppSec) requests an exception for a Finding."""

    reason: str = Field(min_length=1, max_length=10_000)
    expiry_date: date


class WaiverOut(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    requested_by: str
    approved_by: str | None
    reason: str
    expiry_date: date
    status: WaiverStatus
    created_at: datetime

    model_config = {"from_attributes": True}


class WaiverExpiryCheckOut(BaseModel):
    expired_count: int
    reopened_finding_count: int
