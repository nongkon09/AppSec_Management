"""ITSM Connector configuration + ticket lifecycle (Requirement.md FR-7).

Connector CRUD is what "Integration Setting" means in Settings (Section 4: System Admin
manages Integration Connector Configuration). The rest of this module is the closed-loop
machinery FR-7 describes: routing a new Finding to every connector configured for its
Severity Tier (FR-7.2), building ticket content (FR-7.3), and auto-closing tickets when a
Finding is fixed or waived (FR-7.5/7.6).

FR-7.7 asks for "Queue + Retry + Alert ให้ Admin" on a failed call. There is no background
job queue in this codebase to hold a retry for later (only the APScheduler-driven periodic
jobs in app.core.scheduler) — what is implemented is a same-request bounded retry, and a
failure that exhausts its retries is recorded on the Ticket itself (`status="error"`,
`last_error`) and in the audit trail, so it is visible and queryable rather than silently
dropped. Moving this to a real async retry queue is future work, not something this module
pretends to already do.
"""

import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from functools import partial

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.integrations.factory import build_connector
from app.integrations.ticket_connector import TicketDraft
from app.models.finding import Finding, FindingStatus
from app.models.integration import IntegrationConnector
from app.models.ticket import Ticket
from app.schemas.integration import ConnectorCreate, ConnectorUpdate

logger = logging.getLogger(__name__)

_MAX_ATTEMPTS = 3


def _call_with_retry[T](fn: Callable[[], T]) -> tuple[T | None, str | None]:
    """FR-7.7: a bounded same-request retry. Returns (result, None) on success or
    (None, last_error_message) once every attempt has failed."""
    last_error: str | None = None
    for _attempt in range(_MAX_ATTEMPTS):
        try:
            return fn(), None
        except Exception as exc:  # noqa: BLE001 - any connector failure is retried the same way
            last_error = str(exc)
    return None, last_error


# --- Connector configuration (Settings > Integrations) --------------------------------


def list_connectors(db: Session) -> list[IntegrationConnector]:
    return list(
        db.execute(select(IntegrationConnector).order_by(IntegrationConnector.name)).scalars()
    )


def get_connector(db: Session, connector_id: uuid.UUID) -> IntegrationConnector | None:
    return db.get(IntegrationConnector, connector_id)


def create_connector(db: Session, payload: ConnectorCreate, actor: str) -> IntegrationConnector:
    connector = IntegrationConnector(
        name=payload.name,
        connector_type=payload.connector_type,
        base_url=payload.base_url,
        auth_token=payload.auth_token,
        config=payload.config,
        routing_severities=[tier.value for tier in payload.routing_severities],
        is_enabled=payload.is_enabled,
    )
    db.add(connector)
    db.flush()
    record_audit(
        db,
        actor=actor,
        action="integration_connector.create",
        entity_type="integration_connector",
        entity_id=connector.id,
        # Never write auth_token into the audit trail, even on create.
        after={
            "name": connector.name,
            "connector_type": connector.connector_type.value,
            "base_url": connector.base_url,
            "routing_severities": connector.routing_severities,
            "is_enabled": connector.is_enabled,
        },
    )
    db.commit()
    db.refresh(connector)
    return connector


def update_connector(
    db: Session, connector: IntegrationConnector, payload: ConnectorUpdate, actor: str
) -> IntegrationConnector:
    before = {
        "name": connector.name,
        "base_url": connector.base_url,
        "routing_severities": connector.routing_severities,
        "is_enabled": connector.is_enabled,
    }
    changes = payload.model_dump(exclude_unset=True, exclude={"routing_severities"})
    for field, value in changes.items():
        setattr(connector, field, value)
    if payload.routing_severities is not None:
        connector.routing_severities = [tier.value for tier in payload.routing_severities]

    record_audit(
        db,
        actor=actor,
        action="integration_connector.update",
        entity_type="integration_connector",
        entity_id=connector.id,
        before=before,
        after={
            "name": connector.name,
            "base_url": connector.base_url,
            "routing_severities": connector.routing_severities,
            "is_enabled": connector.is_enabled,
        },
    )
    db.commit()
    db.refresh(connector)
    return connector


def delete_connector(db: Session, connector: IntegrationConnector, actor: str) -> None:
    record_audit(
        db,
        actor=actor,
        action="integration_connector.delete",
        entity_type="integration_connector",
        entity_id=connector.id,
        before={"name": connector.name, "connector_type": connector.connector_type.value},
    )
    db.delete(connector)
    db.commit()


# --- Ticket lifecycle (FR-7.3, 7.4, 7.5, 7.6, 7.8) -------------------------------------


def _build_ticket_draft(finding: Finding) -> TicketDraft:
    """FR-7.3: library/version, fixed version, CVE/link, due date, affected app/version."""
    version = finding.app_version
    application = version.application
    summary = finding.cve_id or finding.title or f"Finding {finding.id}"
    component_line = (
        f"{finding.component.component_name} {finding.component.version}"
        if finding.component
        else "N/A (not a component-level finding)"
    )
    lines = [
        f"Application: {application.app_name} ({version.version_label})",
        f"Component: {component_line}",
        f"Fixed version: {finding.fixed_version or 'unknown'}",
        f"Severity: {finding.severity_tier.value}",
        f"CVSS: {finding.cvss if finding.cvss is not None else 'N/A'}",
        f"EPSS: {finding.epss if finding.epss is not None else 'N/A'}",
        f"KEV: {finding.kev_flag}",
    ]
    if finding.reference_url:
        lines.append(f"Reference: {finding.reference_url}")
    if finding.description:
        lines.append(f"\n{finding.description}")
    return TicketDraft(
        summary=f"[{finding.severity_tier.value.upper()}] {summary}",
        description="\n".join(lines),
        due_date=finding.due_date.isoformat() if finding.due_date else None,
        reference=str(finding.id),
    )


def create_ticket(
    db: Session, finding: Finding, connector: IntegrationConnector, actor: str
) -> Ticket:
    """FR-7.8 manual path (and FR-7.2's automatic routing calls this too). Always
    records a Ticket row, even on failure, so a failed push is visible rather than
    silently lost (FR-7.7)."""
    draft = _build_ticket_draft(finding)
    impl = build_connector(connector)
    external_id, error = _call_with_retry(lambda: impl.create_ticket(draft))

    ticket = Ticket(
        finding_id=finding.id,
        connector_id=connector.id,
        external_system=connector.connector_type.value,
        external_id=external_id or "",
        status="error" if error else "open",
        last_error=error,
        last_synced_at=datetime.now(UTC),
    )
    db.add(ticket)
    db.flush()
    record_audit(
        db,
        actor=actor,
        action="ticket.create",
        entity_type="ticket",
        entity_id=ticket.id,
        after={
            "finding_id": str(finding.id),
            "connector": connector.name,
            "external_id": ticket.external_id,
            "status": ticket.status,
            "error": error,
        },
    )
    db.commit()
    db.refresh(ticket)
    return ticket


def route_finding_to_connectors(
    db: Session, finding: Finding, actor: str = "system"
) -> list[Ticket]:
    """FR-7.2: fires a Ticket to every enabled connector configured for this Finding's
    Severity Tier — "รองรับยิงได้มากกว่า 1 ปลายทางพร้อมกัน" (Critical going to both an
    ITSM system and Jira at once is the default policy's example). Skips a connector
    that already has a ticket for this Finding, so re-running routing is idempotent."""
    existing_connector_ids = {
        row[0]
        for row in db.execute(
            select(Ticket.connector_id).where(Ticket.finding_id == finding.id)
        ).all()
        if row[0] is not None
    }
    connectors = db.execute(
        select(IntegrationConnector).where(IntegrationConnector.is_enabled.is_(True))
    ).scalars()

    created: list[Ticket] = []
    for connector in connectors:
        if connector.id in existing_connector_ids:
            continue
        if finding.severity_tier.value not in connector.routing_severities:
            continue
        created.append(create_ticket(db, finding, connector, actor))
    return created


def close_tickets_for_finding(
    db: Session, finding: Finding, *, resolution: str, comment: str, actor: str = "system"
) -> list[Ticket]:
    """FR-7.5 (auto-verified fix) / FR-7.6 (VEX risk-accept): closes every open Ticket
    linked to this Finding across every system it was raised in."""
    tickets = (
        db.execute(select(Ticket).where(Ticket.finding_id == finding.id, Ticket.status == "open"))
        .scalars()
        .all()
    )

    closed: list[Ticket] = []
    for ticket in tickets:
        connector = (
            db.get(IntegrationConnector, ticket.connector_id) if ticket.connector_id else None
        )
        if connector is None:
            # The connector that created this ticket was since deleted; nothing to call.
            continue
        impl = build_connector(connector)
        # functools.partial binds impl/ticket.external_id as soon as it is constructed,
        # here on this loop iteration — unlike a lambda, which would look them up (all
        # pointing at the loop's final value) whenever it is eventually called.
        call = partial(
            impl.close_ticket, ticket.external_id, resolution=resolution, comment=comment
        )
        _, error = _call_with_retry(call)
        before_status = ticket.status
        ticket.status = "error" if error else resolution
        ticket.last_error = error
        ticket.last_synced_at = datetime.now(UTC)
        record_audit(
            db,
            actor=actor,
            action="ticket.auto_close",
            entity_type="ticket",
            entity_id=ticket.id,
            before={"status": before_status},
            after={"status": ticket.status, "error": error},
        )
        closed.append(ticket)
    if closed:
        db.commit()
    return closed


def on_finding_fixed(db: Session, finding: Finding) -> list[Ticket]:
    """FR-7.5: called from the SBOM sync when a re-scan shows a Finding is gone."""
    if finding.status != FindingStatus.FIXED:
        return []
    return close_tickets_for_finding(
        db,
        finding,
        resolution="done",
        comment="Auto-verified by SBOM re-scan",
        actor="system",
    )
