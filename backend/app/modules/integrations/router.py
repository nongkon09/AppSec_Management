import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import CurrentUser, require_roles
from app.models.user import Role
from app.modules.integrations import service
from app.schemas.integration import ConnectorCreate, ConnectorOut, ConnectorUpdate

router = APIRouter(prefix="/integrations", tags=["integrations"])

# Section 4: "System Admin | ... Integration Connector Configuration" — creating,
# editing and deleting a connector (which includes its stored credential) is Admin-only,
# the same split from AppSec's own responsibilities as User/Role management.
_INTEGRATION_ADMIN = (Role.ADMIN,)
# FR-7.8: AppSec creates tickets manually from a Finding, which means AppSec needs to see
# *which* connectors exist to pick one — read-only, and the credential is never returned
# regardless of role (ConnectorOut only ever exposes `auth_token_configured`).
_INTEGRATION_READERS = (Role.APPSEC, Role.ADMIN)


@router.get("/connectors", response_model=list[ConnectorOut])
def list_connectors(
    db: Annotated[Session, Depends(get_db)],
    _current_user: Annotated[CurrentUser, Depends(require_roles(*_INTEGRATION_READERS))],
) -> list[ConnectorOut]:
    return service.list_connectors(db)  # type: ignore[return-value]


@router.post("/connectors", response_model=ConnectorOut, status_code=status.HTTP_201_CREATED)
def create_connector(
    payload: ConnectorCreate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_INTEGRATION_ADMIN))],
) -> ConnectorOut:
    return service.create_connector(db, payload, actor=current_user.username)  # type: ignore[return-value]


@router.patch("/connectors/{connector_id}", response_model=ConnectorOut)
def update_connector(
    connector_id: uuid.UUID,
    payload: ConnectorUpdate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_INTEGRATION_ADMIN))],
) -> ConnectorOut:
    connector = service.get_connector(db, connector_id)
    if connector is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found")
    return service.update_connector(db, connector, payload, actor=current_user.username)  # type: ignore[return-value]


@router.delete("/connectors/{connector_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_connector(
    connector_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_INTEGRATION_ADMIN))],
) -> None:
    connector = service.get_connector(db, connector_id)
    if connector is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found")
    service.delete_connector(db, connector, actor=current_user.username)
