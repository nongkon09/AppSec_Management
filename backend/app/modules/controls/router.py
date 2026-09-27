"""Control Library (docs/risk-exception-design.md 3.6). AppSec maintains it; everyone who
can file or review an exception can read it."""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.db import get_db
from app.core.deps import CurrentUser, get_current_user, require_roles
from app.models.security_control import SecurityControl
from app.models.user import Role
from app.schemas.security_control import ControlCreate, ControlOut, ControlUpdate

router = APIRouter(prefix="/controls", tags=["controls"])


def _to_out(control: SecurityControl) -> ControlOut:
    return ControlOut(
        id=control.id,
        name=control.name,
        description=control.description,
        category=control.category,
        owner=control.owner,
        evidence_url=control.evidence_url,
        effectiveness=control.effectiveness,
        review_due_on=control.review_due_on,
        is_active=control.is_active,
        is_usable=control.is_usable(datetime.now(UTC).date()),
        created_at=control.created_at,
    )


def _snapshot(control: SecurityControl) -> dict[str, object]:
    return {
        "name": control.name,
        "description": control.description,
        "category": control.category.value,
        "owner": control.owner,
        "evidence_url": control.evidence_url,
        "effectiveness": control.effectiveness.value,
        "review_due_on": control.review_due_on.isoformat(),
        "is_active": control.is_active,
    }


@router.get("", response_model=list[ControlOut])
def list_controls(
    db: Annotated[Session, Depends(get_db)],
    _current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> list[ControlOut]:
    rows = db.execute(select(SecurityControl).order_by(SecurityControl.name)).scalars().all()
    return [_to_out(row) for row in rows]


@router.post("", response_model=ControlOut, status_code=status.HTTP_201_CREATED)
def create_control(
    payload: ControlCreate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(Role.APPSEC))],
) -> ControlOut:
    control = SecurityControl(**payload.model_dump())
    db.add(control)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="A control with this name already exists"
        ) from exc
    record_audit(
        db,
        actor=current_user.username,
        action="control.create",
        entity_type="security_control",
        entity_id=control.id,
        after=_snapshot(control),
    )
    db.commit()
    db.refresh(control)
    return _to_out(control)


@router.patch("/{control_id}", response_model=ControlOut)
def update_control(
    control_id: uuid.UUID,
    payload: ControlUpdate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(Role.APPSEC))],
) -> ControlOut:
    control = db.get(SecurityControl, control_id)
    if control is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Control not found")
    before = _snapshot(control)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(control, field, value)
    record_audit(
        db,
        actor=current_user.username,
        action="control.update",
        entity_type="security_control",
        entity_id=control.id,
        before=before,
        after=_snapshot(control),
    )
    db.commit()
    db.refresh(control)
    return _to_out(control)
