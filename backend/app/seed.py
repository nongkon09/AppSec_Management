"""Seed local development data.

Usage:
    python -m app.seed           # default RBAC users (Requirement.md Section 4 roles)
                                 # + the Section 12 default Severity/SLA policy
    python -m app.seed --demo    # additionally seed sample Applications and Findings
"""

import sys
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import Base, SessionLocal, engine
from app.core.security import hash_password
from app.models.component import Component
from app.models.finding import Finding, FindingSource, FindingStatus, SeverityTier
from app.models.inventory import Application, AppType, AppVersion, Criticality, Environment
from app.models.user import ApprovalLevel, Role, User
from app.modules.policy import service as policy_service

DEFAULT_PASSWORD = "ChangeMe123!"

SEED_USERS: list[dict[str, Any]] = [
    {
        "username": "appsec.lead",
        "email": "appsec.lead@example.local",
        "full_name": "AppSec Lead",
        "role": Role.APPSEC,
        "owner_team": None,
        "approval_level": ApprovalLevel.L2,
    },
    {
        "username": "appsec.analyst",
        "email": "appsec.analyst@example.local",
        "full_name": "AppSec Analyst",
        "role": Role.APPSEC,
        "owner_team": None,
        "approval_level": ApprovalLevel.L1,
    },
    {
        "username": "dev.alpha",
        "email": "dev.alpha@example.local",
        "full_name": "Dev Team Alpha",
        "role": Role.DEV_TEAM,
        "owner_team": "Team Alpha",
    },
    {
        "username": "dev.beta",
        "email": "dev.beta@example.local",
        "full_name": "Dev Team Beta",
        "role": Role.DEV_TEAM,
        "owner_team": "Team Beta",
    },
    {
        "username": "legal.officer",
        "email": "legal.officer@example.local",
        "full_name": "Legal Officer",
        "role": Role.LEGAL,
        "owner_team": None,
    },
    {
        "username": "mgmt.exec",
        "email": "mgmt.exec@example.local",
        "full_name": "Management Exec",
        "role": Role.MANAGEMENT,
        "owner_team": None,
        # Acts as CISO / risk executive: second approver for Critical/KEV exceptions.
        "approval_level": ApprovalLevel.L3,
    },
    {
        "username": "audit.viewer",
        "email": "audit.viewer@example.local",
        "full_name": "Compliance Auditor",
        "role": Role.AUDIT,
        "owner_team": None,
    },
    {
        "username": "sysadmin",
        "email": "sysadmin@example.local",
        "full_name": "System Admin",
        "role": Role.ADMIN,
        "owner_team": None,
    },
    {
        "username": "ci.pipeline",
        "email": "ci.pipeline@example.local",
        "full_name": "CI/CD Pipeline",
        "role": Role.PIPELINE,
        "owner_team": None,
    },
]


# Sample inventory for the demo seed. Deliberately spans the Section 2.1 application
# types and both owner teams, so Dev Team data scoping (Section 4) is visible in the UI.
DEMO_APPLICATIONS: list[dict[str, Any]] = [
    {
        "app_name": "Customer Web Portal",
        "app_type": AppType.IN_HOUSE,
        "owner_team": "Team Alpha",
        "business_unit": "Digital Channels",
        "criticality": Criticality.CRITICAL,
        "environment": Environment.PRODUCTION,
        "internet_facing": True,
        "data_classification": "PII + Financial",
        "owner_email": "dev.alpha@example.local",
        "jira_project_key": "CWP",
    },
    {
        "app_name": "Payment Gateway API",
        "app_type": AppType.API,
        "owner_team": "Team Alpha",
        "business_unit": "Payments",
        "criticality": Criticality.CRITICAL,
        "environment": Environment.PRODUCTION,
        "internet_facing": True,
        "data_classification": "Financial (PCI-DSS scope)",
        "owner_email": "dev.alpha@example.local",
        "jira_project_key": "PGW",
    },
    {
        "app_name": "Store Operations Desktop",
        "app_type": AppType.COTS,
        "owner_team": "Team Beta",
        "business_unit": "Store Operations",
        "criticality": Criticality.HIGH,
        "environment": Environment.PRODUCTION,
        "internet_facing": False,
        "data_classification": "PII",
        "owner_email": "dev.beta@example.local",
    },
]

# (component, version, scope, cve, cvss, epss, kev, fixed_version, days_since_detected)
DEMO_SBOM_FINDINGS: list[tuple[str, str, str, str, float, float, bool, str, int]] = [
    (
        "org.apache.logging.log4j:log4j-core",
        "2.14.1",
        "production",
        "CVE-2021-44228",
        10.0,
        0.97,
        True,
        "2.17.1",
        45,
    ),
    (
        "com.fasterxml.jackson.core:jackson-databind",
        "2.9.10",
        "production",
        "CVE-2020-36518",
        7.5,
        0.42,
        False,
        "2.13.2.1",
        20,
    ),
    (
        "org.springframework:spring-web",
        "5.3.17",
        "production",
        "CVE-2024-22243",
        8.1,
        0.09,
        False,
        "5.3.32",
        5,
    ),
    ("lodash", "4.17.15", "production", "CVE-2021-23337", 7.2, 0.01, False, "4.17.21", 60),
    ("axios", "0.21.1", "production", "CVE-2023-45857", 5.3, 0.004, False, "1.6.0", 12),
    ("eslint-utils", "1.4.0", "development", "CVE-2020-7598", 5.6, 0.002, False, "1.4.3", 8),
]


def _seed_demo(db: Session) -> None:
    """Seed sample inventory + Findings so the backlog and dashboard screens are not
    empty before SBOM ingestion (FR-2/FR-3) is wired up."""
    if db.execute(select(Application).limit(1)).scalar_one_or_none() is not None:
        print("Demo data skipped: applications already exist")
        return

    policy = policy_service.get_effective_policy(db)
    today = datetime.now(UTC).date()

    for index, app_data in enumerate(DEMO_APPLICATIONS):
        application = Application(**app_data)
        db.add(application)
        db.flush()

        version = AppVersion(
            application_id=application.id,
            version_label=f"2026.9.{index + 1}",
            commit_sha=f"a1b2c3d{index}",
            environment=Environment.PRODUCTION,
            is_current_production=True,
            is_active=True,
            last_ingested_at=datetime.now(UTC) - timedelta(days=index * 3),
        )
        db.add(version)
        db.flush()

        # Give each Application a different slice of the sample vulnerability set.
        for name, comp_version, scope, cve, cvss, epss, kev, fixed, age_days in DEMO_SBOM_FINDINGS[
            index : index + 3
        ]:
            component = Component(
                app_version_id=version.id,
                component_name=name,
                version=comp_version,
                license="Apache-2.0" if "org.apache" in name else "MIT",
                scope=scope,
                purl=f"pkg:maven/{name}@{comp_version}",
            )
            db.add(component)
            db.flush()

            detected_on = today - timedelta(days=age_days)
            decision = policy_service.evaluate_severity(
                policy, cvss=cvss, epss=epss, kev_flag=kev, scope=scope
            )
            db.add(
                Finding(
                    app_version_id=version.id,
                    component_id=component.id,
                    source=FindingSource.SBOM,
                    cve_id=cve,
                    cvss=cvss,
                    epss=epss,
                    kev_flag=kev,
                    severity_tier=decision.tier,
                    status=FindingStatus.OPEN,
                    policy_version=policy.version,
                    sla_started_on=detected_on,
                    due_date=policy_service.compute_due_date(policy, decision.tier, detected_on),
                    fixed_version=fixed,
                    reference_url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                    first_detected_at=datetime.now(UTC) - timedelta(days=age_days),
                )
            )

        # One Pentest finding, to show the shared backlog required by FR-6.5.6.
        if index == 0:
            db.add(
                Finding(
                    app_version_id=version.id,
                    source=FindingSource.PENTEST,
                    title="Missing account lockout on login endpoint",
                    description=(
                        "Unlimited authentication attempts allow credential stuffing "
                        "against the retail login form."
                    ),
                    severity_tier=SeverityTier.HIGH,
                    status=FindingStatus.OPEN,
                    policy_version=policy.version,
                    sla_started_on=today - timedelta(days=15),
                    due_date=policy_service.compute_due_date(
                        policy, SeverityTier.HIGH, today - timedelta(days=15)
                    ),
                    first_detected_at=datetime.now(UTC) - timedelta(days=15),
                )
            )

    db.commit()
    print(f"Seeded {len(DEMO_APPLICATIONS)} demo applications with components and findings")


def seed(include_demo: bool = False) -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for user_data in SEED_USERS:
            existing = db.query(User).filter(User.username == user_data["username"]).first()
            if existing:
                continue
            db.add(User(hashed_password=hash_password(DEFAULT_PASSWORD), **user_data))
        db.commit()
        print(f"Seeded {len(SEED_USERS)} users (default password: {DEFAULT_PASSWORD})")

        # FR-4.4/FR-5.1: a deployment must always have an effective policy to tier
        # Findings against, before AppSec has configured one.
        policy = policy_service.ensure_default_policy(db)
        print(f"Effective Severity/SLA policy: version {policy.version}")

        if include_demo:
            _seed_demo(db)
    finally:
        db.close()


if __name__ == "__main__":
    seed(include_demo="--demo" in sys.argv[1:])
