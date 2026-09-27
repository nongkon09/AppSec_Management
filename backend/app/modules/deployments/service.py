"""Deployment tracking and active-version resolution (docs/risk-exception-design.md 3.3)."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import exists, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.models.deployment import Deployment, DeploymentSource
from app.models.inventory import Application, AppVersion, Environment

_EPOCH = datetime.min.replace(tzinfo=UTC)


def _as_aware(value: datetime | None) -> datetime:
    if value is None:
        return _EPOCH
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def refresh_active_versions(db: Session, application_id: uuid.UUID) -> None:
    """A version is active while it has an open deployment. An Application that has never
    had a deployment recorded falls back to its most recently ingested version, so the
    backlog is meaningful before any pipeline reports deployments."""
    versions = list(
        db.execute(select(AppVersion).where(AppVersion.application_id == application_id))
        .scalars()
        .all()
    )
    if not versions:
        return

    has_deployments = db.execute(
        select(exists().where(Deployment.application_id == application_id))
    ).scalar_one()

    if has_deployments:
        open_rows = db.execute(
            select(Deployment.app_version_id, Deployment.environment).where(
                Deployment.application_id == application_id, Deployment.ended_at.is_(None)
            )
        ).all()
        active_ids = {row.app_version_id for row in open_rows}
        production_ids = {
            row.app_version_id for row in open_rows if row.environment == Environment.PRODUCTION
        }
        for version in versions:
            version.is_active = version.id in active_ids
            version.is_current_production = version.id in production_ids
    else:
        latest = max(
            versions,
            key=lambda v: (
                v.last_ingested_at is not None,
                _as_aware(v.last_ingested_at or v.created_at),
            ),
        )
        for version in versions:
            version.is_active = version is latest
    db.flush()


def get_or_create_version(
    db: Session, application: Application, version_label: str, environment: Environment
) -> AppVersion:
    version = db.execute(
        select(AppVersion).where(
            AppVersion.application_id == application.id,
            AppVersion.version_label == version_label,
        )
    ).scalar_one_or_none()
    if version is None:
        version = AppVersion(
            application_id=application.id, version_label=version_label, environment=environment
        )
        db.add(version)
        db.flush()
    return version


def record_deployment(
    db: Session,
    *,
    application: Application,
    version: AppVersion,
    environment: Environment,
    source: DeploymentSource,
    actor: str,
    image_digest: str | None = None,
    reference_url: str | None = None,
    deployed_at: datetime | None = None,
) -> Deployment:
    """Closes whatever was running in this environment, records the new deployment and
    recomputes which versions count toward the backlog."""
    when = deployed_at or datetime.now(UTC)
    previous = (
        db.execute(
            select(Deployment).where(
                Deployment.application_id == application.id,
                Deployment.environment == environment,
                Deployment.ended_at.is_(None),
            )
        )
        .scalars()
        .all()
    )
    for row in previous:
        row.ended_at = when

    deployment = Deployment(
        application_id=application.id,
        app_version_id=version.id,
        environment=environment,
        deployed_at=when,
        image_digest=image_digest,
        reference_url=reference_url,
        source=source,
        recorded_by=actor,
    )
    db.add(deployment)
    db.flush()
    refresh_active_versions(db, application.id)

    record_audit(
        db,
        actor=actor,
        action="deployment.record",
        entity_type="deployment",
        entity_id=deployment.id,
        after={
            "application": application.app_name,
            "version": version.version_label,
            "environment": environment.value,
            "image_digest": image_digest,
            "reference_url": reference_url,
            "source": source.value,
            "ended_previous": [str(row.id) for row in previous],
        },
    )
    db.commit()
    db.refresh(deployment)
    return deployment


def end_deployment(db: Session, deployment: Deployment, actor: str) -> Deployment:
    """Marks something as no longer running (e.g. decommissioned) without a replacement."""
    if deployment.ended_at is None:
        deployment.ended_at = datetime.now(UTC)
        db.flush()
        refresh_active_versions(db, deployment.application_id)
        record_audit(
            db,
            actor=actor,
            action="deployment.end",
            entity_type="deployment",
            entity_id=deployment.id,
            after={"ended_at": deployment.ended_at.isoformat()},
        )
        db.commit()
        db.refresh(deployment)
    return deployment


def list_deployments(db: Session, application_id: uuid.UUID) -> list[Deployment]:
    return list(
        db.execute(
            select(Deployment)
            .where(Deployment.application_id == application_id)
            .order_by(Deployment.deployed_at.desc())
        )
        .scalars()
        .all()
    )
