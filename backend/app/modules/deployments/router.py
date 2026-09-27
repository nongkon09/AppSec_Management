import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import CurrentUser, get_current_user, require_roles
from app.models.deployment import Deployment, DeploymentSource
from app.models.inventory import Application, AppVersion
from app.models.user import Role
from app.modules.deployments import service
from app.modules.inventory import service as inventory_service
from app.schemas.deployment import DeploymentCreate, DeploymentOut

router = APIRouter(tags=["deployments"])

_RECORDERS = (Role.PIPELINE, Role.APPSEC, Role.ADMIN, Role.DEV_TEAM)


def deployment_to_out(deployment: Deployment) -> DeploymentOut:
    return DeploymentOut(
        id=deployment.id,
        application_id=deployment.application_id,
        application_name=deployment.application.app_name,
        app_version_id=deployment.app_version_id,
        version_label=deployment.app_version.version_label,
        environment=deployment.environment,
        deployed_at=deployment.deployed_at,
        ended_at=deployment.ended_at,
        image_digest=deployment.image_digest,
        reference_url=deployment.reference_url,
        source=deployment.source,
        recorded_by=deployment.recorded_by,
    )


def _can_touch(current_user: CurrentUser, application: Application) -> bool:
    """Dev Team may only record deployments of their own team's Applications; the
    pipeline account deploys for every team."""
    return current_user.role != Role.DEV_TEAM or application.owner_team == current_user.owner_team


@router.post("/deployments", response_model=DeploymentOut, status_code=status.HTTP_201_CREATED)
def record_deployment(
    payload: DeploymentCreate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_RECORDERS))],
) -> DeploymentOut:
    if payload.application_id is not None:
        application = db.get(Application, payload.application_id)
    else:
        application = db.execute(
            select(Application).where(Application.app_name == payload.application_name)
        ).scalar_one_or_none()
    if application is None or not _can_touch(current_user, application):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")

    if payload.app_version_id is not None:
        version = db.get(AppVersion, payload.app_version_id)
        if version is None or version.application_id != application.id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Version not found")
    else:
        version = service.get_or_create_version(
            db, application, payload.version_label or "", payload.environment
        )

    deployment = service.record_deployment(
        db,
        application=application,
        version=version,
        environment=payload.environment,
        source=DeploymentSource.PIPELINE
        if current_user.role == Role.PIPELINE
        else DeploymentSource.MANUAL,
        actor=current_user.username,
        image_digest=payload.image_digest,
        reference_url=payload.reference_url,
        deployed_at=payload.deployed_at,
    )
    return deployment_to_out(deployment)


@router.post("/deployments/{deployment_id}/end", response_model=DeploymentOut)
def end_deployment(
    deployment_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[
        CurrentUser, Depends(require_roles(Role.APPSEC, Role.ADMIN, Role.DEV_TEAM))
    ],
) -> DeploymentOut:
    deployment = db.get(Deployment, deployment_id)
    if deployment is None or not _can_touch(current_user, deployment.application):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deployment not found")
    return deployment_to_out(service.end_deployment(db, deployment, actor=current_user.username))


@router.get("/applications/{app_id}/deployments", response_model=list[DeploymentOut])
def list_deployments(
    app_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> list[DeploymentOut]:
    application = inventory_service.get_application(db, current_user, app_id)
    if application is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
    return [deployment_to_out(row) for row in service.list_deployments(db, app_id)]
