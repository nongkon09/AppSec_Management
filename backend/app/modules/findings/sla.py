"""SLA anchoring across versions (docs/risk-exception-design.md 3.2).

A Finding's due date is always `sla_started_on` + the SLA days of its effective tier.
`sla_started_on` is inherited from any unresolved Finding with the same issue key in the
same Application, so shipping a new build never restarts the clock.
"""

import uuid
from datetime import date

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.finding import Finding, FindingStatus
from app.models.inventory import AppVersion
from app.models.policy import PolicySet
from app.modules.policy import service as policy_service


def resolve_sla_start(
    db: Session,
    application_id: uuid.UUID,
    issue_key: str,
    *,
    today: date,
    exclude_finding_id: uuid.UUID | None = None,
) -> date:
    """Earliest SLA anchor among this issue's unresolved Findings in the Application,
    or today when there are none (a first sighting, or a reintroduction after a real fix)."""
    stmt = (
        select(func.min(Finding.sla_started_on))
        .join(AppVersion, Finding.app_version_id == AppVersion.id)
        .where(
            AppVersion.application_id == application_id,
            Finding.issue_key == issue_key,
            Finding.status != FindingStatus.FIXED,
        )
    )
    if exclude_finding_id is not None:
        stmt = stmt.where(Finding.id != exclude_finding_id)
    earliest = db.execute(stmt).scalar_one_or_none()
    return min(earliest, today) if earliest is not None else today


def refresh_due_date(policy: PolicySet, finding: Finding) -> None:
    """Recompute the due date from the anchor and the effective (residual or original) tier."""
    finding.due_date = policy_service.compute_due_date(
        policy, finding.effective_severity_tier, finding.sla_started_on
    )
