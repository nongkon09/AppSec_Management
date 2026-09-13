from pydantic import BaseModel

from app.models.user import Role


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    username: str
    email: str
    full_name: str
    role: Role
    owner_team: str | None = None

    model_config = {"from_attributes": True}
