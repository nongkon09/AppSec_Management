from pydantic import BaseModel

from app.models.user import ApprovalLevel, Role


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    username: str
    email: str
    full_name: str
    role: Role
    owner_team: str | None = None
    # The UI shows Checker actions from this; the server re-checks on every decision.
    approval_level: ApprovalLevel = ApprovalLevel.NONE

    model_config = {"from_attributes": True}
