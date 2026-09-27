import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import CurrentUser, get_current_user, require_roles
from app.models.risk_exception import ExceptionStatus, RiskException
from app.models.user import Role
from app.modules.exceptions import service
from app.schemas.risk_exception import (
    BypassCreate,
    ControlSummaryOut,
    ExceptionApprovalOut,
    ExceptionBypassOut,
    ExceptionCreate,
    ExceptionDecisionIn,
    ExceptionEndIn,
    ExceptionItemOut,
    ExceptionOut,
    ExceptionSweepOut,
    PaginatedExceptions,
)

router = APIRouter(prefix="/exceptions", tags=["exceptions"])


def _to_out(exception: RiskException, current_user: CurrentUser) -> ExceptionOut:
    refusal = service.approve_refusal(exception, current_user)
    return ExceptionOut(
        **{
            field: getattr(exception, field)
            for field in (
                "id",
                "reference",
                "exception_type",
                "status",
                "requested_by",
                "created_at",
                "reason",
                "evidence",
                "compensating_measures",
                "vex_justification",
                "original_severity_tier",
                "kev_involved",
                "residual_severity_tier",
                "expires_on",
                "required_approvals",
                "required_min_level",
                "required_top_level",
                "decided_at",
                "ended_by",
                "ended_reason",
                "is_legacy",
                "needs_review",
            )
        },
        items=[
            ExceptionItemOut(
                application_id=item.application_id,
                application_name=item.application.app_name,
                issue_key=item.issue_key,
                label=item.label,
                origin_finding_id=item.origin_finding_id,
            )
            for item in exception.items
        ],
        approvals=[ExceptionApprovalOut.model_validate(a) for a in exception.approvals],
        bypasses=[ExceptionBypassOut.model_validate(b) for b in exception.bypasses],
        controls=[ControlSummaryOut.model_validate(c) for c in exception.controls],
        can_approve=refusal is None,
        approve_refusal=refusal,
    )


def _translate(exc: Exception) -> HTTPException:
    if isinstance(exc, service.ExceptionForbiddenError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if isinstance(exc, service.ExceptionConflictError):
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))


_ERRORS = (service.ExceptionError, service.ExceptionConflictError, service.ExceptionForbiddenError)
_READERS = (
    Role.APPSEC,
    Role.DEV_TEAM,
    Role.MANAGEMENT,
    Role.AUDIT,
    Role.ADMIN,
    Role.PIPELINE,
)


def _load(db: Session, current_user: CurrentUser, exception_id: uuid.UUID) -> RiskException:
    exception = service.get_exception(db, current_user, exception_id)
    if exception is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exception not found")
    return exception


@router.post("", response_model=ExceptionOut, status_code=status.HTTP_201_CREATED)
def submit_exception(
    payload: ExceptionCreate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> ExceptionOut:
    try:
        exception = service.create_exception(db, current_user, payload)
    except _ERRORS as exc:
        raise _translate(exc) from exc
    return _to_out(exception, current_user)


@router.get("", response_model=PaginatedExceptions)
def list_exceptions(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_READERS))],
    exception_status: Annotated[list[ExceptionStatus] | None, Query(alias="status")] = None,
    awaiting_me: bool = False,
    mine: bool = False,
    application_id: uuid.UUID | None = None,
    finding_id: uuid.UUID | None = None,
    skip: int = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> PaginatedExceptions:
    items, total = service.list_exceptions(
        db,
        current_user,
        statuses=exception_status,
        awaiting_me=awaiting_me,
        mine=mine,
        application_id=application_id,
        finding_id=finding_id,
        skip=skip,
        limit=limit,
    )
    return PaginatedExceptions(items=[_to_out(e, current_user) for e in items], total=total)


@router.get("/by-reference/{reference}", response_model=ExceptionOut)
def get_by_reference(
    reference: str,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_READERS))],
) -> ExceptionOut:
    """What DevOps checks before a manual bypass: status, scope and expiry by reference."""
    exception = service.get_by_reference(db, current_user, reference)
    if exception is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exception not found")
    return _to_out(exception, current_user)


@router.post("/sweep", response_model=ExceptionSweepOut)
def run_sweep(
    db: Annotated[Session, Depends(get_db)],
    _current_user: Annotated[CurrentUser, Depends(require_roles(Role.APPSEC, Role.ADMIN))],
) -> ExceptionSweepOut:
    expired, closed, flagged = service.sweep(db)
    return ExceptionSweepOut(expired=expired, closed=closed, flagged_for_review=flagged)


@router.get("/{exception_id}", response_model=ExceptionOut)
def get_exception(
    exception_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_READERS))],
) -> ExceptionOut:
    return _to_out(_load(db, current_user, exception_id), current_user)


@router.post("/{exception_id}/approve", response_model=ExceptionOut)
def approve(
    exception_id: uuid.UUID,
    payload: ExceptionDecisionIn,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> ExceptionOut:
    exception = _load(db, current_user, exception_id)
    try:
        updated = service.decide(db, exception, current_user, approve=True, comment=payload.comment)
    except _ERRORS as exc:
        raise _translate(exc) from exc
    return _to_out(updated, current_user)


@router.post("/{exception_id}/reject", response_model=ExceptionOut)
def reject(
    exception_id: uuid.UUID,
    payload: ExceptionDecisionIn,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> ExceptionOut:
    exception = _load(db, current_user, exception_id)
    try:
        updated = service.decide(
            db, exception, current_user, approve=False, comment=payload.comment
        )
    except _ERRORS as exc:
        raise _translate(exc) from exc
    return _to_out(updated, current_user)


@router.post("/{exception_id}/withdraw", response_model=ExceptionOut)
def withdraw(
    exception_id: uuid.UUID,
    payload: ExceptionEndIn,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> ExceptionOut:
    exception = _load(db, current_user, exception_id)
    try:
        updated = service.withdraw(db, exception, current_user, payload.reason)
    except _ERRORS as exc:
        raise _translate(exc) from exc
    return _to_out(updated, current_user)


@router.post("/{exception_id}/revoke", response_model=ExceptionOut)
def revoke(
    exception_id: uuid.UUID,
    payload: ExceptionEndIn,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> ExceptionOut:
    exception = _load(db, current_user, exception_id)
    try:
        updated = service.revoke(db, exception, current_user, payload.reason)
    except _ERRORS as exc:
        raise _translate(exc) from exc
    return _to_out(updated, current_user)


@router.post(
    "/{exception_id}/bypasses", response_model=ExceptionOut, status_code=status.HTTP_201_CREATED
)
def record_bypass(
    exception_id: uuid.UUID,
    payload: BypassCreate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[
        CurrentUser, Depends(require_roles(Role.DEV_TEAM, Role.APPSEC, Role.ADMIN))
    ],
) -> ExceptionOut:
    exception = _load(db, current_user, exception_id)
    try:
        updated = service.record_bypass(db, exception, current_user, payload)
    except _ERRORS as exc:
        raise _translate(exc) from exc
    return _to_out(updated, current_user)
