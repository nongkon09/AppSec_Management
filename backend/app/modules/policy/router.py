from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import CurrentUser, get_current_user, require_roles
from app.models.user import Role
from app.modules.policy import service
from app.schemas.policy import (
    PolicySetCreate,
    PolicySetOut,
    SeverityEvaluationRequest,
    SeverityEvaluationResult,
)

router = APIRouter(prefix="/policies", tags=["policy"])

# Section 4: AppSec owns Severity/SLA policy; System Admin covers system configuration;
# Audit and Management may read it to interpret the Findings they see.
_POLICY_READERS = (Role.APPSEC, Role.ADMIN, Role.AUDIT, Role.MANAGEMENT)
_POLICY_WRITERS = (Role.APPSEC, Role.ADMIN)


@router.get("", response_model=list[PolicySetOut])
def list_policy_versions(
    db: Annotated[Session, Depends(get_db)],
    _current_user: Annotated[CurrentUser, Depends(require_roles(*_POLICY_READERS))],
) -> list[PolicySetOut]:
    """Full version history, newest first (NFR Auditability)."""
    service.ensure_default_policy(db)
    return service.list_policies(db)  # type: ignore[return-value]


@router.get("/effective", response_model=PolicySetOut)
def get_effective_policy(
    db: Annotated[Session, Depends(get_db)],
    _current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> PolicySetOut:
    """The policy currently in force. Readable by every authenticated role, since Dev
    Teams need it to understand the SLA attached to their Findings (FR-10.2)."""
    return service.get_effective_policy(db)  # type: ignore[return-value]


@router.post("", response_model=PolicySetOut, status_code=status.HTTP_201_CREATED)
def publish_policy_version(
    payload: PolicySetCreate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_POLICY_WRITERS))],
) -> PolicySetOut:
    """FR-5.1: publish a new Severity/SLA policy version. Existing versions are never
    edited, so historical decisions stay reproducible."""
    return service.create_policy_set(db, payload, actor=current_user.username)  # type: ignore[return-value]


@router.post("/evaluate", response_model=SeverityEvaluationResult)
def evaluate(
    payload: SeverityEvaluationRequest,
    db: Annotated[Session, Depends(get_db)],
    _current_user: Annotated[CurrentUser, Depends(require_roles(*_POLICY_WRITERS))],
) -> SeverityEvaluationResult:
    """Dry-run the rule engine against hypothetical CVSS/EPSS/KEV values, so a policy can
    be sanity-checked before it is published (FR-4.1)."""
    if payload.policy_version is None:
        policy = service.get_effective_policy(db)
    else:
        found = service.get_policy_by_version(db, payload.policy_version)
        if found is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy version {payload.policy_version} not found",
            )
        policy = found

    decision = service.evaluate_severity(
        policy,
        cvss=payload.cvss,
        epss=payload.epss,
        kev_flag=payload.kev_flag,
        scope=payload.scope,
    )
    return SeverityEvaluationResult(
        severity_tier=decision.tier,
        matched_rule=decision.matched_rule,
        downgraded_for_dev_scope=decision.downgraded_for_dev_scope,
        policy_version=policy.version,
        sla_days=service.sla_days_for_tier(policy, decision.tier),
        due_date=service.compute_due_date(policy, decision.tier),
    )
