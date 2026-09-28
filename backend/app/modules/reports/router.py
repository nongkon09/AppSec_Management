from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import CurrentUser, require_roles
from app.models.user import Role
from app.modules.reports import service
from app.schemas.report import ExecutiveSummary

router = APIRouter(prefix="/reports", tags=["reports"])

_READERS = (Role.APPSEC, Role.MANAGEMENT, Role.AUDIT, Role.ADMIN, Role.DEV_TEAM)


@router.get("/executive-summary", response_model=ExecutiveSummary)
def executive_summary(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_READERS))],
    month: Annotated[str, Query(pattern=r"^\d{4}-\d{2}$", description="YYYY-MM")],
) -> ExecutiveSummary:
    """Monthly figures for leadership. A Dev Team reader gets their own team's view."""
    try:
        year, month_number = service.parse_month(month, datetime.now(UTC).date())
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)
        ) from error
    return service.executive_summary(db, current_user, year, month_number)
