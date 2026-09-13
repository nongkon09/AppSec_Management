import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import CurrentUser
from app.models.inventory import Application, AppVersion
from app.models.user import Role
from app.schemas.inventory import ApplicationCreate, ApplicationUpdate, AppVersionCreate


def list_applications(
    db: Session, current_user: CurrentUser, skip: int = 0, limit: int = 50
) -> tuple[list[Application], int]:
    """FR-1.4 + Section 4: Dev Team is scoped to their own owner_team; other roles see all."""
    stmt = select(Application)
    if current_user.role == Role.DEV_TEAM and current_user.owner_team:
        stmt = stmt.where(Application.owner_team == current_user.owner_team)

    total = len(db.execute(stmt).scalars().all())
    items = (
        db.execute(stmt.order_by(Application.app_name).offset(skip).limit(limit)).scalars().all()
    )
    return list(items), total


def get_application(
    db: Session, current_user: CurrentUser, app_id: uuid.UUID
) -> Application | None:
    app = db.get(Application, app_id)
    if app is None:
        return None
    if current_user.role == Role.DEV_TEAM and app.owner_team != current_user.owner_team:
        return None
    return app


def create_application(db: Session, payload: ApplicationCreate) -> Application:
    app = Application(**payload.model_dump())
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


def update_application(db: Session, app: Application, payload: ApplicationUpdate) -> Application:
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(app, field, value)
    db.commit()
    db.refresh(app)
    return app


def get_or_create_application_by_name(
    db: Session, app_name: str, owner_team: str, app_type: str = "in_house"
) -> tuple[Application, bool]:
    """FR-1.5: Auto-create Application when SBOM arrives for an unregistered project.
    The returned bool indicates whether the Application was newly created (needs
    ownership confirmation by AppSec, per FR-1.5)."""
    app = db.execute(
        select(Application).where(Application.app_name == app_name)
    ).scalar_one_or_none()
    if app is not None:
        return app, False
    app = Application(
        app_name=app_name,
        app_type=app_type,
        owner_team=owner_team,
        ownership_confirmed=False,
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app, True


def create_app_version(
    db: Session, application: Application, payload: AppVersionCreate
) -> AppVersion:
    version = AppVersion(application_id=application.id, **payload.model_dump())
    db.add(version)
    db.commit()
    db.refresh(version)
    return version


def list_app_versions(db: Session, application_id: uuid.UUID) -> list[AppVersion]:
    stmt = (
        select(AppVersion)
        .where(AppVersion.application_id == application_id)
        .order_by(AppVersion.created_at.desc())
    )
    return list(db.execute(stmt).scalars().all())


def mark_ingested(db: Session, version: AppVersion) -> AppVersion:
    """FR-2.3/2.4: record ingestion timestamp and clear the stale flag."""
    version.last_ingested_at = datetime.now(UTC)
    version.is_stale = False
    db.commit()
    db.refresh(version)
    return version
