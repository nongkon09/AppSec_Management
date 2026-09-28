"""SCIM 2.0 provisioning endpoint for Microsoft Entra ID (RFC 7643/7644, the subset the
Entra provisioning service uses: Users and Groups with filter, PATCH, PUT and DELETE).

Entra creates, updates and disables accounts here, and keeps group membership in step,
so a person's role follows the groups they are in (docs/entra-id.md). SCIM only ever sees
Entra ID accounts: a local account (break-glass admin, CI/CD) is invisible to it and can
never be changed or disabled through it.
"""

import re
import secrets
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.config import get_settings
from app.core.db import get_db
from app.models.directory import DirectoryGroup, DirectoryGroupMember
from app.models.user import AuthSource, User
from app.modules.directory import service

ACTOR = "entra-scim"
SCIM_JSON = "application/scim+json"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
MAX_RESULTS = 200


class ScimError(Exception):
    def __init__(self, status_code: int, detail: str, scim_type: str | None = None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.scim_type = scim_type


def _require_token(authorization: Annotated[str | None, Header()] = None) -> None:
    token = get_settings().scim_bearer_token
    if not token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SCIM is not set up")
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(supplied.strip(), token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


router = APIRouter(prefix="/scim/v2", tags=["scim"], dependencies=[Depends(_require_token)])


def _json(body: dict[str, Any], code: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=code, media_type=SCIM_JSON)


def _error(exc: ScimError) -> JSONResponse:
    body: dict[str, Any] = {
        "schemas": [ERROR_SCHEMA],
        "status": str(exc.status_code),
        "detail": exc.detail,
    }
    if exc.scim_type:
        body["scimType"] = exc.scim_type
    return _json(body, exc.status_code)


async def _body(request: Request) -> dict[str, Any]:
    try:
        data = await request.json()
    except ValueError as exc:
        raise ScimError(400, "Body is not valid JSON", "invalidSyntax") from exc
    if not isinstance(data, dict):
        raise ScimError(400, "Body must be a JSON object", "invalidSyntax")
    return data


# --- Representation ---------------------------------------------------------------------


def _meta(kind: str, row: Any, request: Request) -> dict[str, Any]:
    base = get_settings().api_base_url
    return {
        "resourceType": kind,
        "created": row.created_at.isoformat() if row.created_at else None,
        "lastModified": row.updated_at.isoformat() if row.updated_at else None,
        "location": f"{base}/scim/v2/{kind}s/{row.id}",
    }


def _user_out(user: User, request: Request) -> dict[str, Any]:
    return {
        "schemas": [USER_SCHEMA],
        "id": str(user.id),
        "externalId": user.scim_external_id,
        "userName": user.username,
        "displayName": user.full_name,
        "name": {"formatted": user.full_name},
        "active": user.is_active,
        "emails": [{"value": user.email, "type": "work", "primary": True}],
        "roles": [{"value": role, "primary": False} for role in user.directory_roles or []],
        "meta": _meta("User", user, request),
    }


def _group_out(
    db: Session, group: DirectoryGroup, request: Request, with_members: bool = True
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schemas": [GROUP_SCHEMA],
        "id": str(group.id),
        "externalId": group.external_id,
        "displayName": group.display_name,
        "meta": _meta("Group", group, request),
    }
    if with_members:
        rows = db.execute(
            select(User.id, User.username)
            .join(DirectoryGroupMember, DirectoryGroupMember.user_id == User.id)
            .where(DirectoryGroupMember.group_id == group.id)
        ).all()
        body["members"] = [{"value": str(uid), "display": name} for uid, name in rows]
    return body


def _list(resources: list[dict[str, Any]], total: int, start: int) -> JSONResponse:
    return _json(
        {
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": len(resources),
            "Resources": resources,
        }
    )


# --- Filters: `attribute eq "value"`, the only form Entra sends -------------------------

_FILTER = re.compile(r'^\s*([\w.]+)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$', re.IGNORECASE)


def _parse_filter(expression: str | None) -> tuple[str, str] | None:
    if not expression:
        return None
    match = _FILTER.match(expression)
    if not match:
        raise ScimError(400, f"Unsupported filter: {expression}", "invalidFilter")
    return match.group(1).lower(), match.group(2).replace('\\"', '"')


def _paging(start_index: int, count: int) -> tuple[int, int]:
    return max(start_index, 1), max(0, min(count, MAX_RESULTS))


# --- Value helpers ----------------------------------------------------------------------


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    raise ScimError(400, f"Not a boolean: {value!r}", "invalidValue")


def _primary_email(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, list) and value:
        chosen = next((e for e in value if isinstance(e, dict) and e.get("primary")), value[0])
        return chosen.get("value") if isinstance(chosen, dict) else str(chosen)
    return None


def _role_values(value: Any) -> list[str]:
    items = value if isinstance(value, list) else [value]
    values = []
    for item in items:
        if isinstance(item, dict):
            item = item.get("value")
        if item:
            values.append(str(item))
    return values


def _name_from(value: dict[str, Any]) -> str | None:
    formatted = value.get("formatted")
    if formatted:
        return str(formatted)
    parts = [value.get("givenName"), value.get("familyName")]
    joined = " ".join(str(p) for p in parts if p)
    return joined or None


# --- Users ------------------------------------------------------------------------------


def _users_query():
    return select(User).where(User.auth_source == AuthSource.ENTRA)


def _get_user(db: Session, user_id: str) -> User:
    try:
        key = uuid.UUID(user_id)
    except ValueError as exc:
        raise ScimError(404, "User not found") from exc
    user = db.execute(_users_query().where(User.id == key)).scalar_one_or_none()
    if user is None:
        raise ScimError(404, "User not found")
    return user


def _check_unique(db: Session, user: User | None, username: str, email: str) -> None:
    clash = select(User.id).where(
        (func.lower(User.username) == username.lower()) | (func.lower(User.email) == email.lower())
    )
    if user is not None:
        clash = clash.where(User.id != user.id)
    if db.execute(clash).first():
        raise ScimError(409, f"{username} or {email} is already in use", "uniqueness")


def _set_active(db: Session, user: User, active: bool) -> None:
    if user.is_active != active:
        record_audit(
            db,
            actor=ACTOR,
            action="user.update",
            entity_type="user",
            entity_id=user.id,
            before={"is_active": user.is_active},
            after={"is_active": active},
        )
        user.is_active = active


def _apply_user_attribute(db: Session, user: User, op: str, path: str, value: Any) -> None:
    key = path.lower()
    if key == "active":
        _set_active(db, user, _as_bool(value))
    elif key == "username":
        _check_unique(db, user, str(value), user.email)
        user.username = str(value).strip().lower()
    elif key == "externalid":
        user.scim_external_id = None if op == "remove" else str(value)
    elif key in ("displayname", "name.formatted"):
        if value:
            user.full_name = str(value)
    elif key == "name" and isinstance(value, dict):
        name = _name_from(value)
        if name:
            user.full_name = name
    elif key.startswith("emails"):
        email = _primary_email(value)
        if email and op != "remove":
            _check_unique(db, user, user.username, email)
            user.email = email.strip().lower()
    elif key.startswith("roles"):
        values = _role_values(value) if value is not None else []
        current = list(user.directory_roles or [])
        if op == "remove":
            user.directory_roles = [r for r in current if r not in values] if values else []
        elif op == "add" and key == "roles":
            user.directory_roles = current + [v for v in values if v not in current]
        else:
            user.directory_roles = values
    # Anything else (title, phoneNumbers, enterprise extension, ...) is not stored.


def _apply_user_body(db: Session, user: User, body: dict[str, Any]) -> None:
    for key, value in body.items():
        if key in ("schemas", "id", "meta", "password"):
            continue
        _apply_user_attribute(db, user, "replace", key, value)


@router.get("/Users")
def list_users(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    filter: str | None = None,
    startIndex: int = 1,  # noqa: N803 - SCIM parameter name
    count: int = 100,
) -> Response:
    try:
        parsed = _parse_filter(filter)
    except ScimError as exc:
        return _error(exc)
    query = _users_query()
    if parsed:
        attribute, value = parsed
        column = {
            "username": func.lower(User.username),
            "externalid": User.scim_external_id,
            "emails.value": func.lower(User.email),
            "id": None,
        }.get(attribute, False)
        if column is False:
            return _error(ScimError(400, f"Cannot filter on {attribute}", "invalidFilter"))
        if column is None:
            try:
                query = query.where(User.id == uuid.UUID(value))
            except ValueError:
                return _list([], 0, 1)
        else:
            needle = value if attribute == "externalid" else value.lower()
            query = query.where(column == needle)
    start, size = _paging(startIndex, count)
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    users = db.execute(query.order_by(User.username).offset(start - 1).limit(size)).scalars()
    return _list([_user_out(u, request) for u in users], total, start)


@router.post("/Users")
async def create_user(request: Request, db: Annotated[Session, Depends(get_db)]) -> Response:
    try:
        body = await _body(request)
        username = str(body.get("userName") or "").strip().lower()
        if not username:
            raise ScimError(400, "userName is required", "invalidValue")
        email = (_primary_email(body.get("emails")) or username).strip().lower()
        _check_unique(db, None, username, email)
        user = User(
            username=username,
            email=email,
            full_name=str(
                body.get("displayName") or _name_from(body.get("name") or {}) or username
            ),
            hashed_password=None,
            role=None,
            auth_source=AuthSource.ENTRA,
            scim_external_id=body.get("externalId"),
            directory_roles=_role_values(body.get("roles") or []),
            is_active=_as_bool(body.get("active", True)),
        )
        db.add(user)
        db.flush()
        service.apply_access(db, user, ACTOR)
        record_audit(
            db,
            actor=ACTOR,
            action="user.create",
            entity_type="user",
            entity_id=user.id,
            after={
                "username": user.username,
                "auth_source": "entra",
                "role": user.role.value if user.role else None,
                "is_active": user.is_active,
            },
        )
        db.commit()
        db.refresh(user)
    except ScimError as exc:
        db.rollback()
        return _error(exc)
    return _json(_user_out(user, request), 201)


@router.get("/Users/{user_id}")
def get_user(user_id: str, request: Request, db: Annotated[Session, Depends(get_db)]) -> Response:
    try:
        return _json(_user_out(_get_user(db, user_id), request))
    except ScimError as exc:
        return _error(exc)


@router.put("/Users/{user_id}")
async def replace_user(
    user_id: str, request: Request, db: Annotated[Session, Depends(get_db)]
) -> Response:
    try:
        user = _get_user(db, user_id)
        body = await _body(request)
        body.setdefault("roles", [])
        _apply_user_body(db, user, body)
        service.apply_access(db, user, ACTOR)
        db.commit()
        db.refresh(user)
    except ScimError as exc:
        db.rollback()
        return _error(exc)
    return _json(_user_out(user, request))


@router.patch("/Users/{user_id}")
async def patch_user(
    user_id: str, request: Request, db: Annotated[Session, Depends(get_db)]
) -> Response:
    try:
        user = _get_user(db, user_id)
        body = await _body(request)
        for operation in body.get("Operations") or []:
            op = str(operation.get("op", "")).lower()
            if op not in ("add", "replace", "remove"):
                raise ScimError(400, f"Unsupported op {op}", "invalidSyntax")
            path = operation.get("path")
            value = operation.get("value")
            if path:
                _apply_user_attribute(db, user, op, str(path), value)
            elif isinstance(value, dict):
                _apply_user_body(db, user, value)
        service.apply_access(db, user, ACTOR)
        db.commit()
        db.refresh(user)
    except ScimError as exc:
        db.rollback()
        return _error(exc)
    return _json(_user_out(user, request))


@router.delete("/Users/{user_id}")
def delete_user(user_id: str, db: Annotated[Session, Depends(get_db)]) -> Response:
    """Accounts are never deleted: audit entries and approvals refer to them by name.
    Deleting in Entra disables the account and drops its groups here."""
    try:
        user = _get_user(db, user_id)
    except ScimError as exc:
        return _error(exc)
    _set_active(db, user, False)
    db.execute(delete(DirectoryGroupMember).where(DirectoryGroupMember.user_id == user.id))
    user.directory_roles = []
    service.apply_access(db, user, ACTOR)
    db.commit()
    return Response(status_code=204)


# --- Groups -----------------------------------------------------------------------------


def _get_group(db: Session, group_id: str) -> DirectoryGroup:
    try:
        key = uuid.UUID(group_id)
    except ValueError as exc:
        raise ScimError(404, "Group not found") from exc
    group = db.get(DirectoryGroup, key)
    if group is None:
        raise ScimError(404, "Group not found")
    return group


def _member_ids(value: Any) -> set[uuid.UUID]:
    ids = set()
    for item in value if isinstance(value, list) else [value]:
        raw = item.get("value") if isinstance(item, dict) else item
        try:
            ids.add(uuid.UUID(str(raw)))
        except ValueError:
            continue
    return ids


def _current_members(db: Session, group: DirectoryGroup) -> set[uuid.UUID]:
    return set(
        db.execute(
            select(DirectoryGroupMember.user_id).where(DirectoryGroupMember.group_id == group.id)
        ).scalars()
    )


def _set_members(db: Session, group: DirectoryGroup, wanted: set[uuid.UUID]) -> set[uuid.UUID]:
    """Make the membership exactly `wanted` (Entra accounts only). Returns who changed."""
    wanted = (
        set(
            db.execute(
                select(User.id).where(User.id.in_(wanted), User.auth_source == AuthSource.ENTRA)
            ).scalars()
        )
        if wanted
        else set()
    )
    current = _current_members(db, group)
    if current - wanted:
        db.execute(
            delete(DirectoryGroupMember).where(
                DirectoryGroupMember.group_id == group.id,
                DirectoryGroupMember.user_id.in_(current - wanted),
            )
        )
    for user_id in wanted - current:
        db.add(DirectoryGroupMember(group_id=group.id, user_id=user_id))
    db.flush()
    return current ^ wanted


def _refresh_access(db: Session, user_ids: set[uuid.UUID]) -> None:
    if not user_ids:
        return
    rules = service.load_rules(db)
    for user in db.execute(select(User).where(User.id.in_(user_ids))).scalars():
        service.apply_access(db, user, ACTOR, rules)


_MEMBER_FILTER = re.compile(r'^members\[value eq "([^"]+)"\]$', re.IGNORECASE)


@router.get("/Groups")
def list_groups(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    filter: str | None = None,
    excludedAttributes: str | None = None,  # noqa: N803 - SCIM parameter name
    startIndex: int = 1,  # noqa: N803
    count: int = 100,
) -> Response:
    try:
        parsed = _parse_filter(filter)
    except ScimError as exc:
        return _error(exc)
    query = select(DirectoryGroup)
    if parsed:
        attribute, value = parsed
        if attribute == "displayname":
            query = query.where(DirectoryGroup.display_name == value)
        elif attribute == "externalid":
            query = query.where(DirectoryGroup.external_id == value)
        elif attribute == "id":
            try:
                query = query.where(DirectoryGroup.id == uuid.UUID(value))
            except ValueError:
                return _list([], 0, 1)
        else:
            return _error(ScimError(400, f"Cannot filter on {attribute}", "invalidFilter"))
    with_members = "members" not in (excludedAttributes or "").lower()
    start, size = _paging(startIndex, count)
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    groups = db.execute(
        query.order_by(DirectoryGroup.display_name).offset(start - 1).limit(size)
    ).scalars()
    return _list([_group_out(db, g, request, with_members) for g in groups], total, start)


@router.post("/Groups")
async def create_group(request: Request, db: Annotated[Session, Depends(get_db)]) -> Response:
    try:
        body = await _body(request)
        name = body.get("displayName")
        # Entra's default mapping sends the group object id as externalId; that is the
        # value sign-in tokens carry, so mappings work with either source.
        external_id = str(body.get("externalId") or name or "").strip()
        if not external_id:
            raise ScimError(400, "externalId or displayName is required", "invalidValue")
        existing = db.execute(
            select(DirectoryGroup).where(DirectoryGroup.external_id == external_id)
        ).scalar_one_or_none()
        if existing is not None and existing.display_name:
            raise ScimError(409, f"Group {external_id} already exists", "uniqueness")
        # A group first seen in a sign-in token (or a mapping) is adopted, not duplicated.
        group = service.ensure_group(db, external_id, str(name) if name else None)
        changed = _set_members(db, group, _member_ids(body.get("members") or []))
        _refresh_access(db, changed)
        db.commit()
        db.refresh(group)
    except ScimError as exc:
        db.rollback()
        return _error(exc)
    return _json(_group_out(db, group, request), 201)


@router.get("/Groups/{group_id}")
def get_group(
    group_id: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    excludedAttributes: str | None = None,  # noqa: N803
) -> Response:
    try:
        group = _get_group(db, group_id)
    except ScimError as exc:
        return _error(exc)
    return _json(
        _group_out(db, group, request, "members" not in (excludedAttributes or "").lower())
    )


@router.put("/Groups/{group_id}")
async def replace_group(
    group_id: str, request: Request, db: Annotated[Session, Depends(get_db)]
) -> Response:
    try:
        group = _get_group(db, group_id)
        body = await _body(request)
        if body.get("displayName"):
            group.display_name = str(body["displayName"])
        if body.get("externalId"):
            group.external_id = str(body["externalId"])
        changed = _set_members(db, group, _member_ids(body.get("members") or []))
        _refresh_access(db, changed)
        db.commit()
        db.refresh(group)
    except ScimError as exc:
        db.rollback()
        return _error(exc)
    return _json(_group_out(db, group, request))


@router.patch("/Groups/{group_id}")
async def patch_group(
    group_id: str, request: Request, db: Annotated[Session, Depends(get_db)]
) -> Response:
    try:
        group = _get_group(db, group_id)
        body = await _body(request)
        members = _current_members(db, group)
        for operation in body.get("Operations") or []:
            op = str(operation.get("op", "")).lower()
            path = str(operation.get("path") or "")
            value = operation.get("value")
            single = _MEMBER_FILTER.match(path)
            if single:
                if op == "remove":
                    members -= _member_ids(single.group(1))
            elif path.lower() == "members":
                ids = _member_ids(value) if value is not None else set()
                if op == "add":
                    members |= ids
                elif op == "remove":
                    members = members - ids if value is not None else set()
                elif op == "replace":
                    members = ids
            elif path.lower() == "displayname" or (not path and isinstance(value, dict)):
                attrs = value if isinstance(value, dict) else {"displayName": value}
                if attrs.get("displayName"):
                    group.display_name = str(attrs["displayName"])
                if attrs.get("externalId"):
                    group.external_id = str(attrs["externalId"])
                if "members" in attrs:
                    members = _member_ids(attrs["members"] or [])
            elif path.lower() == "externalid" and value:
                group.external_id = str(value)
        changed = _set_members(db, group, members)
        _refresh_access(db, changed)
        db.commit()
    except ScimError as exc:
        db.rollback()
        return _error(exc)
    return Response(status_code=204)


@router.delete("/Groups/{group_id}")
def delete_group(group_id: str, db: Annotated[Session, Depends(get_db)]) -> Response:
    try:
        group = _get_group(db, group_id)
    except ScimError as exc:
        return _error(exc)
    former = _current_members(db, group)
    db.execute(delete(DirectoryGroupMember).where(DirectoryGroupMember.group_id == group.id))
    db.delete(group)
    db.flush()
    _refresh_access(db, former)
    db.commit()
    return Response(status_code=204)


# --- Discovery --------------------------------------------------------------------------


@router.get("/ServiceProviderConfig")
def service_provider_config() -> Response:
    return _json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": MAX_RESULTS},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "OAuth Bearer Token",
                    "description": "The secret token from the Provisioning page",
                    "primary": True,
                }
            ],
        }
    )
