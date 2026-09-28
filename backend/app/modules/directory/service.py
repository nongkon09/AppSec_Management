"""Entra ID accounts: group membership, role mappings, and keeping each account's role
in step with them. Every change to an account's access is audited (FR-11.1)."""

import uuid

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.models.directory import DirectoryGroup, DirectoryGroupMember, MappingKind, RoleMapping
from app.models.user import ApprovalLevel, AuthSource, User
from app.modules.directory import access
from app.schemas.directory import RoleMappingIn


class MappingError(ValueError):
    pass


class MappingConflict(ValueError):
    pass


def load_rules(db: Session) -> list[access.Rule]:
    return [
        access.Rule(m.kind, m.value, m.role, m.approval_level, m.owner_team)
        for m in db.execute(select(RoleMapping)).scalars()
    ]


def group_ids(db: Session, user: User) -> list[str]:
    return list(
        db.execute(
            select(DirectoryGroup.external_id)
            .join(DirectoryGroupMember, DirectoryGroupMember.group_id == DirectoryGroup.id)
            .where(DirectoryGroupMember.user_id == user.id)
        ).scalars()
    )


def resolve_for(
    db: Session, user: User, rules: list[access.Rule] | None = None
) -> access.Access | None:
    if rules is None:
        rules = load_rules(db)
    return access.resolve(rules, user.directory_roles or [], group_ids(db, user))


def apply_access(
    db: Session, user: User, actor: str, rules: list[access.Rule] | None = None
) -> access.Access | None:
    """Set the account's role from the mappings. Flushes, does not commit."""
    if user.auth_source != AuthSource.ENTRA:
        return None
    granted = resolve_for(db, user, rules)
    before = _access_state(user)
    user.role = granted.role if granted else None
    user.approval_level = granted.approval_level if granted else ApprovalLevel.NONE
    user.owner_team = granted.owner_team if granted else None
    after = _access_state(user)
    if before != after:
        after["matched"] = list(granted.matched) if granted else []
        record_audit(
            db,
            actor=actor,
            action="user.directory_access",
            entity_type="user",
            entity_id=user.id,
            before=before,
            after=after,
        )
    db.flush()
    return granted


def recompute_all(db: Session, actor: str) -> int:
    """After a mapping change: re-decide every Entra account. Returns how many changed."""
    rules = load_rules(db)
    changed = 0
    users = db.execute(select(User).where(User.auth_source == AuthSource.ENTRA)).scalars()
    for user in users:
        before = _access_state(user)
        apply_access(db, user, actor, rules)
        changed += int(_access_state(user) != before)
    return changed


def _access_state(user: User) -> dict:
    return {
        "role": user.role.value if user.role else None,
        "approval_level": user.approval_level.value,
        "owner_team": user.owner_team,
    }


# --- Groups -----------------------------------------------------------------------------


def ensure_group(db: Session, external_id: str, display_name: str | None = None) -> DirectoryGroup:
    group = db.execute(
        select(DirectoryGroup).where(DirectoryGroup.external_id == external_id)
    ).scalar_one_or_none()
    if group is None:
        group = DirectoryGroup(external_id=external_id, display_name=display_name)
        db.add(group)
        db.flush()
    elif display_name and group.display_name != display_name:
        group.display_name = display_name
    return group


def set_user_groups(db: Session, user: User, external_ids: list[str]) -> None:
    """Replace the account's memberships with the groups listed in its sign-in token."""
    wanted = {ensure_group(db, external_id).id for external_id in set(external_ids)}
    current = set(
        db.execute(
            select(DirectoryGroupMember.group_id).where(DirectoryGroupMember.user_id == user.id)
        ).scalars()
    )
    if current - wanted:
        db.execute(
            delete(DirectoryGroupMember).where(
                DirectoryGroupMember.user_id == user.id,
                DirectoryGroupMember.group_id.in_(current - wanted),
            )
        )
    for group_id in wanted - current:
        db.add(DirectoryGroupMember(group_id=group_id, user_id=user.id))
    db.flush()


def list_groups(db: Session) -> list[DirectoryGroup]:
    return list(
        db.execute(
            select(DirectoryGroup).order_by(DirectoryGroup.display_name, DirectoryGroup.external_id)
        ).scalars()
    )


def groups_of(db: Session, user_id: uuid.UUID) -> list[DirectoryGroup]:
    return list(
        db.execute(
            select(DirectoryGroup)
            .join(DirectoryGroupMember, DirectoryGroupMember.group_id == DirectoryGroup.id)
            .where(DirectoryGroupMember.user_id == user_id)
            .order_by(DirectoryGroup.display_name)
        ).scalars()
    )


# --- Role mappings ----------------------------------------------------------------------


def list_mappings(db: Session) -> list[RoleMapping]:
    return list(
        db.execute(select(RoleMapping).order_by(RoleMapping.kind, RoleMapping.value)).scalars()
    )


def _mapping_state(mapping: RoleMapping) -> dict:
    return {
        "kind": mapping.kind.value,
        "value": mapping.value,
        "role": mapping.role.value,
        "approval_level": mapping.approval_level.value,
        "owner_team": mapping.owner_team,
    }


def _validate(db: Session, payload: RoleMappingIn, exclude: uuid.UUID | None = None) -> None:
    errors = access.rule_errors(payload.role, payload.approval_level, payload.owner_team)
    if errors:
        raise MappingError(" ".join(errors))
    clash = select(RoleMapping).where(
        RoleMapping.kind == payload.kind, RoleMapping.value == payload.value
    )
    if exclude is not None:
        clash = clash.where(RoleMapping.id != exclude)
    if db.execute(clash).first():
        raise MappingConflict("A mapping for this app role or group already exists.")


def _apply(mapping: RoleMapping, payload: RoleMappingIn) -> None:
    mapping.kind = payload.kind
    mapping.value = payload.value
    mapping.role = payload.role
    mapping.approval_level = payload.approval_level
    mapping.owner_team = payload.owner_team.strip() if payload.owner_team else None


def create_mapping(db: Session, payload: RoleMappingIn, actor: str) -> tuple[RoleMapping, int]:
    _validate(db, payload)
    mapping = RoleMapping()
    _apply(mapping, payload)
    if payload.kind == MappingKind.GROUP:
        ensure_group(db, payload.value)
    db.add(mapping)
    db.flush()
    record_audit(
        db,
        actor=actor,
        action="role_mapping.create",
        entity_type="role_mapping",
        entity_id=mapping.id,
        after=_mapping_state(mapping),
    )
    changed = recompute_all(db, actor)
    db.commit()
    db.refresh(mapping)
    return mapping, changed


def update_mapping(
    db: Session, mapping: RoleMapping, payload: RoleMappingIn, actor: str
) -> tuple[RoleMapping, int]:
    _validate(db, payload, exclude=mapping.id)
    before = _mapping_state(mapping)
    _apply(mapping, payload)
    if payload.kind == MappingKind.GROUP:
        ensure_group(db, payload.value)
    db.flush()
    record_audit(
        db,
        actor=actor,
        action="role_mapping.update",
        entity_type="role_mapping",
        entity_id=mapping.id,
        before=before,
        after=_mapping_state(mapping),
    )
    changed = recompute_all(db, actor)
    db.commit()
    db.refresh(mapping)
    return mapping, changed


def delete_mapping(db: Session, mapping: RoleMapping, actor: str) -> int:
    record_audit(
        db,
        actor=actor,
        action="role_mapping.delete",
        entity_type="role_mapping",
        entity_id=mapping.id,
        before=_mapping_state(mapping),
    )
    db.delete(mapping)
    db.flush()
    changed = recompute_all(db, actor)
    db.commit()
    return changed
