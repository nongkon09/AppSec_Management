import uuid
from datetime import datetime

from pydantic import BaseModel, Field, model_validator

from app.models.user import ApprovalLevel, Role


class UserCreate(BaseModel):
    """Requirement.md Section 4: System Admin manages User/Role.

    Local username/password creation — the auth stub this platform ships until SSO
    (SAML2/OIDC, Section 7) replaces it. The admin sets the initial password directly;
    there is no self-service signup.
    """

    username: str = Field(min_length=3, max_length=255)
    email: str = Field(min_length=3, max_length=255)
    full_name: str = Field(min_length=1, max_length=255)
    role: Role
    owner_team: str | None = Field(default=None, max_length=255)
    password: str = Field(min_length=8, max_length=255)
    # Who may act as Checker on risk decisions (docs/risk-exception-design.md 3.5).
    approval_level: ApprovalLevel = ApprovalLevel.NONE

    @model_validator(mode="after")
    def _dev_team_needs_owner_team(self) -> "UserCreate":
        # Section 4: Dev Team / Tech Lead visibility is scoped by OwnerTeam — an
        # unassigned Dev Team account would see nothing (deps.py fails closed on
        # owner_team=None), which is never what creating one is meant to do.
        if self.role == Role.DEV_TEAM and not self.owner_team:
            raise ValueError("owner_team is required for the Development Team role")
        return self


class UserUpdate(BaseModel):
    """Username is not editable: it is the durable identifier audit entries and
    OwnerTeam scoping are keyed on."""

    full_name: str | None = Field(default=None, min_length=1, max_length=255)
    email: str | None = Field(default=None, min_length=3, max_length=255)
    role: Role | None = None
    owner_team: str | None = Field(default=None, max_length=255)
    is_active: bool | None = None
    approval_level: ApprovalLevel | None = None


class PasswordReset(BaseModel):
    new_password: str = Field(min_length=8, max_length=255)


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    full_name: str
    role: Role
    owner_team: str | None
    is_active: bool
    approval_level: ApprovalLevel
    created_at: datetime

    model_config = {"from_attributes": True}


class PaginatedUsers(BaseModel):
    items: list[UserOut]
    total: int = Field(ge=0)
