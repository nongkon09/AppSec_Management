"""Audit Trail helper (Requirement.md FR-11).

Every critical action (Ingest SBOM, ticket create/close, Waiver approval, Policy
change, Go-Live approval) must be recorded with actor, timestamp and before/after
values. Entries are append-only: nothing in the application layer updates or
deletes an AuditLog row.
"""

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.models.audit import AuditLog


def record_audit(
    db: Session,
    *,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: str | uuid.UUID,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> AuditLog:
    """Append an audit entry to the caller's open transaction.

    The row is flushed but not committed, so the audit trail commits atomically
    with the change it describes (FR-11.1) — a committed action can never be
    missing its audit entry.
    """
    entry = AuditLog(
        actor=actor,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        before_value=before,
        after_value=after,
    )
    db.add(entry)
    db.flush()
    return entry
