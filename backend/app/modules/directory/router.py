"""System Admin screens for Entra ID: connection status and role mappings."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.deps import CurrentUser, require_roles
from app.models.directory import DirectoryGroup, DirectoryGroupMember, MappingKind, RoleMapping
from app.models.user import Role, User
from app.modules.directory import service
from app.schemas.directory import (
    DirectoryAccount,
    DirectoryGroupOut,
    DirectoryStatus,
    RoleMappingIn,
    RoleMappingOut,
    RoleMappingSaved,
)

router = APIRouter(prefix="/directory", tags=["directory"])

_ADMIN = Depends(require_roles(Role.ADMIN))


@router.get("/status", response_model=DirectoryStatus)
def directory_status(_user: Annotated[CurrentUser, _ADMIN]) -> DirectoryStatus:
    settings = get_settings()
    return DirectoryStatus(
        sso_enabled=settings.entra_enabled,
        scim_enabled=settings.scim_enabled,
        local_login_enabled=settings.local_login_enabled,
        jit_provisioning=settings.entra_jit_provisioning,
        tenant_id=settings.entra_tenant_id or None,
        client_id=settings.entra_client_id or None,
        redirect_uri=f"{settings.api_base_url}/auth/sso/callback",
        scim_url=f"{settings.api_base_url}/scim/v2",
    )


def _group_names(db: Session) -> dict[str, str | None]:
    return {g.external_id: g.display_name for g in db.execute(select(DirectoryGroup)).scalars()}


def _to_out(mapping: RoleMapping, names: dict[str, str | None]) -> RoleMappingOut:
    return RoleMappingOut(
        id=mapping.id,
        kind=mapping.kind,
        value=mapping.value,
        role=mapping.role,
        approval_level=mapping.approval_level,
        owner_team=mapping.owner_team,
        group_name=names.get(mapping.value) if mapping.kind == MappingKind.GROUP else None,
    )


@router.get("/mappings", response_model=list[RoleMappingOut])
def list_mappings(
    db: Annotated[Session, Depends(get_db)], _user: Annotated[CurrentUser, _ADMIN]
) -> list[RoleMappingOut]:
    names = _group_names(db)
    return [_to_out(m, names) for m in service.list_mappings(db)]


def _translate(error: ValueError) -> HTTPException:
    code = (
        status.HTTP_409_CONFLICT
        if isinstance(error, service.MappingConflict)
        else status.HTTP_422_UNPROCESSABLE_ENTITY
    )
    return HTTPException(status_code=code, detail=str(error))


@router.post("/mappings", response_model=RoleMappingSaved, status_code=status.HTTP_201_CREATED)
def create_mapping(
    payload: RoleMappingIn,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[CurrentUser, _ADMIN],
) -> RoleMappingSaved:
    try:
        mapping, changed = service.create_mapping(db, payload, user.username)
    except (service.MappingError, service.MappingConflict) as error:
        raise _translate(error) from error
    return RoleMappingSaved(mapping=_to_out(mapping, _group_names(db)), users_changed=changed)


def _load(db: Session, mapping_id: uuid.UUID) -> RoleMapping:
    mapping = db.get(RoleMapping, mapping_id)
    if mapping is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mapping not found")
    return mapping


@router.put("/mappings/{mapping_id}", response_model=RoleMappingSaved)
def update_mapping(
    mapping_id: uuid.UUID,
    payload: RoleMappingIn,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[CurrentUser, _ADMIN],
) -> RoleMappingSaved:
    mapping = _load(db, mapping_id)
    try:
        mapping, changed = service.update_mapping(db, mapping, payload, user.username)
    except (service.MappingError, service.MappingConflict) as error:
        raise _translate(error) from error
    return RoleMappingSaved(mapping=_to_out(mapping, _group_names(db)), users_changed=changed)


@router.delete("/mappings/{mapping_id}", response_model=RoleMappingSaved)
def delete_mapping(
    mapping_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[CurrentUser, _ADMIN],
) -> RoleMappingSaved:
    changed = service.delete_mapping(db, _load(db, mapping_id), user.username)
    return RoleMappingSaved(mapping=None, users_changed=changed)


@router.get("/groups", response_model=list[DirectoryGroupOut])
def list_groups(
    db: Annotated[Session, Depends(get_db)], _user: Annotated[CurrentUser, _ADMIN]
) -> list[DirectoryGroupOut]:
    rows = db.execute(
        select(DirectoryGroupMember.group_id, func.count()).group_by(DirectoryGroupMember.group_id)
    ).all()
    counts: dict[uuid.UUID, int] = {group_id: count for group_id, count in rows}
    return [
        DirectoryGroupOut(
            id=g.id,
            external_id=g.external_id,
            display_name=g.display_name,
            member_count=counts.get(g.id, 0),
        )
        for g in service.list_groups(db)
    ]


@router.get("/users/{user_id}", response_model=DirectoryAccount)
def directory_account(
    user_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[CurrentUser, _ADMIN],
) -> DirectoryAccount:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    granted = service.resolve_for(db, user)
    return DirectoryAccount(
        app_roles=list(user.directory_roles or []),
        groups=[
            DirectoryGroupOut(
                id=g.id, external_id=g.external_id, display_name=g.display_name, member_count=0
            )
            for g in service.groups_of(db, user.id)
        ],
        matched=list(granted.matched) if granted else [],
    )
