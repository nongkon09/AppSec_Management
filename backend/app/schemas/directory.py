import uuid

from pydantic import BaseModel, Field, field_validator

from app.models.directory import MappingKind
from app.models.user import ApprovalLevel, Role


class RoleMappingIn(BaseModel):
    kind: MappingKind
    # App role value ("AppSec.Lead") or group object id.
    value: str = Field(min_length=1, max_length=255)
    role: Role
    approval_level: ApprovalLevel = ApprovalLevel.NONE
    owner_team: str | None = Field(default=None, max_length=255)

    @field_validator("value")
    @classmethod
    def _strip(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("enter the app role value or group object id")
        return value


class RoleMappingOut(BaseModel):
    id: uuid.UUID
    kind: MappingKind
    value: str
    role: Role
    approval_level: ApprovalLevel
    owner_team: str | None
    # The group's name when SCIM has sent it; None for app roles and unnamed groups.
    group_name: str | None = None


class RoleMappingSaved(BaseModel):
    mapping: RoleMappingOut | None
    # Entra accounts whose role changed because of this save.
    users_changed: int


class DirectoryGroupOut(BaseModel):
    id: uuid.UUID
    external_id: str
    display_name: str | None
    member_count: int


class DirectoryStatus(BaseModel):
    """What the admin needs to register the app in Entra ID. No secrets."""

    sso_enabled: bool
    scim_enabled: bool
    local_login_enabled: bool
    jit_provisioning: bool
    tenant_id: str | None
    client_id: str | None
    redirect_uri: str
    scim_url: str


class DirectoryAccount(BaseModel):
    """Why an Entra account has the role it has."""

    app_roles: list[str]
    groups: list[DirectoryGroupOut]
    # The mappings that granted the current role, as "group:<id>" / "app_role:<value>".
    matched: list[str]
