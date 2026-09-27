import uuid
from datetime import date, datetime

from pydantic import BaseModel, Field

from app.models.security_control import ControlCategory, ControlEffectiveness


class ControlCreate(BaseModel):
    name: str = Field(min_length=3, max_length=255)
    description: str | None = Field(default=None, max_length=5_000)
    category: ControlCategory
    owner: str = Field(min_length=1, max_length=255)
    evidence_url: str | None = Field(default=None, max_length=1024)
    effectiveness: ControlEffectiveness
    review_due_on: date


class ControlUpdate(BaseModel):
    description: str | None = Field(default=None, max_length=5_000)
    owner: str | None = Field(default=None, min_length=1, max_length=255)
    evidence_url: str | None = Field(default=None, max_length=1024)
    effectiveness: ControlEffectiveness | None = None
    review_due_on: date | None = None
    is_active: bool | None = None


class ControlOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    category: ControlCategory
    owner: str
    evidence_url: str | None
    effectiveness: ControlEffectiveness
    review_due_on: date
    is_active: bool
    is_usable: bool
    created_at: datetime
