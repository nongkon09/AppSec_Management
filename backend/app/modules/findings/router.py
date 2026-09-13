import uuid
from datetime import UTC, date, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import CurrentUser, get_current_user, require_roles
from app.models.finding import Finding, FindingStatus, SeverityTier
from app.models.inventory import AppVersion
from app.models.ticket import Ticket
from app.models.user import Role
from app.modules.findings import service
from app.modules.integrations import service as integrations_service
from app.schemas.finding import (
    BacklogSummary,
    FindingCreate,
    FindingOut,
    FindingUpdate,
    GlobalVexSuppressRequest,
    GlobalVexSuppressResult,
    PaginatedFindings,
    VexUpdate,
)
from app.schemas.integration import ManualTicketCreate, TicketOut

router = APIRouter(prefix="/findings", tags=["findings"])


def _to_out(finding: Finding, today: date | None = None) -> FindingOut:
    """Flatten the Application → Version → Component chain the backlog table needs
    (FR-10.5 drill-down) into a single row."""
    as_of = today or datetime.now(UTC).date()
    version = finding.app_version
    application = version.application
    component = finding.component
    return FindingOut(
        **{
            column: getattr(finding, column)
            for column in (
                "id",
                "app_version_id",
                "component_id",
                "pentest_project_id",
                "source",
                "cve_id",
                "title",
                "description",
                "cvss",
                "epss",
                "kev_flag",
                "severity_tier",
                "status",
                "vex_status",
                "vex_justification",
                "due_date",
                "policy_version",
                "fixed_version",
                "reference_url",
                "remediation_plan",
                "remediation_plan_updated_by",
                "remediation_plan_updated_at",
                "first_detected_at",
                "fixed_at",
            )
        },
        application_id=application.id,
        application_name=application.app_name,
        owner_team=application.owner_team,
        version_label=version.version_label,
        component_name=component.component_name if component else None,
        component_version=component.version if component else None,
        component_scope=component.scope if component else None,
        is_overdue=finding.is_overdue(as_of),
        days_until_due=(finding.due_date - as_of).days if finding.due_date else None,
    )


@router.get("", response_model=PaginatedFindings)
def list_findings(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    application_id: uuid.UUID | None = None,
    app_version_id: uuid.UUID | None = None,
    severity: Annotated[list[SeverityTier] | None, Query()] = None,
    finding_status: Annotated[list[FindingStatus] | None, Query()] = None,
    source: str | None = None,
    sla_status: Annotated[str | None, Query(pattern="^(overdue|within_sla)$")] = None,
    search: str | None = None,
    skip: int = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> PaginatedFindings:
    """FR-5.4 / FR-10.2 backlog list. Dev Team results are scoped to their own
    Applications; AppSec and the read-only roles see the whole organisation."""
    items, total = service.list_findings(
        db,
        current_user,
        application_id=application_id,
        app_version_id=app_version_id,
        severity=severity,
        status=finding_status,
        source=source,
        sla_status=sla_status,
        search=search,
        skip=skip,
        limit=limit,
    )
    return PaginatedFindings(items=[_to_out(item) for item in items], total=total)


@router.get("/summary", response_model=BacklogSummary)
def get_backlog_summary(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    application_id: uuid.UUID | None = None,
) -> BacklogSummary:
    """FR-5.4 Backlog View counts, scoped the same way as the list endpoint."""
    return service.backlog_summary(db, current_user, application_id=application_id)


@router.post("", response_model=FindingOut, status_code=status.HTTP_201_CREATED)
def create_finding(
    payload: FindingCreate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(Role.APPSEC, Role.ADMIN))],
) -> FindingOut:
    """Manual intake for Pentest/SAST Findings (FR-6.5.5, FR-6.5.6). SBOM Findings arrive
    through the Dependency-Track sync instead, never through this endpoint."""
    version = db.get(AppVersion, payload.app_version_id)
    if version is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Application version not found"
        )
    try:
        finding = service.create_finding(db, payload, actor=current_user.username)
    except service.PentestFindingNotAllowedError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return _to_out(finding)


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> FindingOut:
    finding = service.get_finding(db, current_user, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return _to_out(finding)


@router.patch("/{finding_id}", response_model=FindingOut)
def update_remediation_plan(
    finding_id: uuid.UUID,
    payload: FindingUpdate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[
        CurrentUser, Depends(require_roles(Role.APPSEC, Role.ADMIN, Role.DEV_TEAM))
    ],
) -> FindingOut:
    """FR-10.2: the Dev Team owning the Application maintains the remediation plan.
    Scoping in `service.get_finding` already prevents a Dev Team user from reaching
    another team's Finding — the read-only roles (Legal/Management/Audit) are excluded
    outright per Section 4."""
    finding = service.get_finding(db, current_user, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    updated = service.update_remediation_plan(db, finding, payload, actor=current_user.username)
    return _to_out(updated)


_VEX_MANAGERS = (Role.APPSEC, Role.ADMIN)


@router.patch("/{finding_id}/vex", response_model=FindingOut)
def update_vex_status(
    finding_id: uuid.UUID,
    payload: VexUpdate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_VEX_MANAGERS))],
) -> FindingOut:
    """FR-8.1/8.2: AppSec/Admin-only — being able to call this endpoint at all *is*
    the approval step; Dev Team has no path to change VEX status directly."""
    finding = service.get_finding(db, current_user, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    updated = service.update_vex_status(db, finding, payload, actor=current_user.username)
    return _to_out(updated)


@router.post("/vex/global-suppress", response_model=GlobalVexSuppressResult)
def global_suppress_vex(
    payload: GlobalVexSuppressRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_VEX_MANAGERS))],
) -> GlobalVexSuppressResult:
    """FR-8.3: the single Global Suppression mechanism, applied across every
    Application sharing this CVE (no per-Application scoping — AppSec/Admin already
    see the whole organisation)."""
    updated = service.global_suppress_vex(
        db,
        payload.cve_id,
        VexUpdate(vex_status=payload.vex_status, vex_justification=payload.vex_justification),
        actor=current_user.username,
    )
    return GlobalVexSuppressResult(affected_finding_count=len(updated))


@router.get("/{finding_id}/tickets", response_model=list[TicketOut])
def list_finding_tickets(
    finding_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> list[TicketOut]:
    """FR-7.4: the cross-reference view — every external ticket raised for this
    Finding, across every connector it was routed to. Scoped the same as the Finding
    itself (a Dev Team user cannot see tickets for another team's Finding)."""
    finding = service.get_finding(db, current_user, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    tickets = (
        db.execute(
            select(Ticket).where(Ticket.finding_id == finding_id).order_by(Ticket.created_at)
        )
        .scalars()
        .all()
    )
    return tickets  # type: ignore[return-value]


@router.post("/{finding_id}/tickets", response_model=TicketOut, status_code=status.HTTP_201_CREATED)
def create_finding_ticket(
    finding_id: uuid.UUID,
    payload: ManualTicketCreate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(Role.APPSEC, Role.ADMIN))],
) -> TicketOut:
    """FR-7.8: manual ticket creation from a Finding, for the edge cases automatic
    routing (FR-7.2) does not cover."""
    finding = service.get_finding(db, current_user, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    connector = integrations_service.get_connector(db, payload.connector_id)
    if connector is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found")
    ticket = integrations_service.create_ticket(db, finding, connector, actor=current_user.username)
    return ticket  # type: ignore[return-value]
