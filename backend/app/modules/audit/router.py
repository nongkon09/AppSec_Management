"""Audit Trail read + export API (Requirement.md FR-11.2, FR-10.4).

Read-only by design: the platform never exposes a way to modify or delete an audit
entry, which is what makes the log immutable in the FR-11.1 sense.
"""

import csv
import io
import json
from datetime import date, datetime, time
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import CurrentUser, require_roles
from app.models.audit import AuditLog
from app.models.user import Role
from app.schemas.audit import AuditLogOut, PaginatedAuditLogs

router = APIRouter(prefix="/audit-logs", tags=["audit"])

# Section 4: Compliance/Audit is read-only across the system and may export the trail;
# AppSec and System Admin need it operationally.
_AUDIT_READERS = (Role.AUDIT, Role.APPSEC, Role.ADMIN)

CSV_COLUMNS = (
    "timestamp",
    "actor",
    "action",
    "entity_type",
    "entity_id",
    "before_value",
    "after_value",
)


def _filtered_query(
    *,
    entity_type: str | None,
    entity_id: str | None,
    actor: str | None,
    action: str | None,
    date_from: date | None,
    date_to: date | None,
) -> Select[tuple[AuditLog]]:
    stmt = select(AuditLog)
    if entity_type:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    if entity_id:
        stmt = stmt.where(AuditLog.entity_id == entity_id)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    if action:
        stmt = stmt.where(AuditLog.action.ilike(f"%{action}%"))
    if date_from:
        stmt = stmt.where(AuditLog.timestamp >= datetime.combine(date_from, time.min))
    if date_to:
        # Inclusive upper bound: a report "to 30 September" must contain that whole day.
        stmt = stmt.where(AuditLog.timestamp <= datetime.combine(date_to, time.max))
    return stmt


@router.get("", response_model=PaginatedAuditLogs)
def list_audit_logs(
    db: Annotated[Session, Depends(get_db)],
    _current_user: Annotated[CurrentUser, Depends(require_roles(*_AUDIT_READERS))],
    entity_type: str | None = None,
    entity_id: str | None = None,
    actor: str | None = None,
    action: str | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    skip: int = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> PaginatedAuditLogs:
    stmt = _filtered_query(
        entity_type=entity_type,
        entity_id=entity_id,
        actor=actor,
        action=action,
        date_from=date_from,
        date_to=date_to,
    )
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = (
        db.execute(
            stmt.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).offset(skip).limit(limit)
        )
        .scalars()
        .all()
    )
    return PaginatedAuditLogs(items=[AuditLogOut.model_validate(row) for row in rows], total=total)


@router.get("/export")
def export_audit_logs(
    db: Annotated[Session, Depends(get_db)],
    _current_user: Annotated[CurrentUser, Depends(require_roles(*_AUDIT_READERS))],
    entity_type: str | None = None,
    entity_id: str | None = None,
    actor: str | None = None,
    action: str | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
) -> StreamingResponse:
    """FR-11.2: export the trail for a period so Internal Audit / the regulator can
    review it outside the platform. Streamed in pages to keep memory flat for the
    multi-year retention windows required by Section 7 (Data Retention)."""
    stmt = _filtered_query(
        entity_type=entity_type,
        entity_id=entity_id,
        actor=actor,
        action=action,
        date_from=date_from,
        date_to=date_to,
    ).order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())

    def rows():
        buffer = io.StringIO()
        writer = csv.writer(buffer)

        def flush() -> str:
            value = buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)
            return value

        writer.writerow(CSV_COLUMNS)
        yield flush()

        for entry in db.execute(stmt).scalars().yield_per(500):
            writer.writerow(
                [
                    entry.timestamp.isoformat(),
                    entry.actor,
                    entry.action,
                    entry.entity_type,
                    entry.entity_id,
                    json.dumps(entry.before_value, ensure_ascii=False)
                    if entry.before_value
                    else "",
                    json.dumps(entry.after_value, ensure_ascii=False) if entry.after_value else "",
                ]
            )
            yield flush()

    filename = f"audit-log-{datetime.now().date().isoformat()}.csv"
    return StreamingResponse(
        rows(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
