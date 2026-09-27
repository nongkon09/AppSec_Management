"""First-run bootstrap for a clean production install (docs/deployment-guide.md).

Unlike `app.seed`, which creates demo accounts with a shared default password, this
creates exactly one System Admin from the environment and the default Severity/SLA
policy — nothing else. It is idempotent: once any user exists it leaves users alone,
so the entrypoint can run it on every start and a rotated admin password is never
overwritten.

Environment:
    INITIAL_ADMIN_USERNAME   default "admin"
    INITIAL_ADMIN_EMAIL      default "admin@localhost"
    INITIAL_ADMIN_PASSWORD   required on the first start only (at least 12 characters)
"""

import os
import sys

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.db import SessionLocal
from app.core.security import hash_password
from app.models.user import Role, User
from app.modules.policy import service as policy_service

MIN_PASSWORD_LENGTH = 12


class BootstrapError(Exception):
    pass


def bootstrap(db: Session, env: dict[str, str]) -> list[str]:
    """Returns what was done, one line per action, for the container log."""
    done: list[str] = []
    if db.execute(select(func.count()).select_from(User)).scalar_one() == 0:
        password = env.get("INITIAL_ADMIN_PASSWORD", "")
        if len(password) < MIN_PASSWORD_LENGTH:
            raise BootstrapError(
                f"No users exist yet: set INITIAL_ADMIN_PASSWORD (at least "
                f"{MIN_PASSWORD_LENGTH} characters) for the first start."
            )
        username = env.get("INITIAL_ADMIN_USERNAME") or "admin"
        admin = User(
            username=username,
            email=env.get("INITIAL_ADMIN_EMAIL") or "admin@localhost",
            full_name="System Administrator",
            role=Role.ADMIN,
            owner_team=None,
            hashed_password=hash_password(password),
        )
        db.add(admin)
        db.flush()
        record_audit(
            db,
            actor=policy_service.SYSTEM_ACTOR,
            action="user.bootstrap_admin",
            entity_type="user",
            entity_id=admin.id,
            after={"username": username, "role": Role.ADMIN.value},
        )
        db.commit()
        done.append(f"Created initial admin '{username}'")

    policy = policy_service.ensure_default_policy(db)
    done.append(f"Effective Severity/SLA policy: version {policy.version}")
    return done


def main() -> int:
    db = SessionLocal()
    try:
        for line in bootstrap(db, dict(os.environ)):
            print(line)
    except BootstrapError as error:
        print(f"Bootstrap failed: {error}", file=sys.stderr)
        return 1
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
