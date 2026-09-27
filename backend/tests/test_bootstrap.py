import pytest
from sqlalchemy import select

from app.bootstrap import BootstrapError, bootstrap
from app.core import scheduler
from app.models.audit import AuditLog
from app.models.policy import PolicySet
from app.models.user import Role, User


def test_first_start_creates_only_admin_and_policy(db_session):
    lines = bootstrap(db_session, {"INITIAL_ADMIN_PASSWORD": "a-long-secret-123"})

    users = db_session.execute(select(User)).scalars().all()
    assert [(u.username, u.role) for u in users] == [("admin", Role.ADMIN)]
    assert db_session.execute(select(PolicySet)).scalars().all()
    assert any("admin" in line for line in lines)
    actions = db_session.execute(select(AuditLog.action)).scalars().all()
    assert "user.bootstrap_admin" in actions


def test_first_start_refuses_short_password(db_session):
    with pytest.raises(BootstrapError):
        bootstrap(db_session, {"INITIAL_ADMIN_PASSWORD": "short"})
    assert db_session.execute(select(User)).first() is None


def test_rerun_leaves_existing_users_alone(db_session, make_user):
    make_user("appsec.lead", Role.APPSEC)
    # No password needed once anyone exists, and no second admin appears.
    bootstrap(db_session, {})
    usernames = db_session.execute(select(User.username)).scalars().all()
    assert usernames == ["appsec.lead"]


def test_worker_registers_every_job():
    from apscheduler.schedulers.background import BackgroundScheduler

    sched = BackgroundScheduler()
    scheduler.add_jobs(sched)
    assert {job.id for job in sched.get_jobs()} == {
        "dependency_track_sync",
        "stale_sbom_check",
        "exception_sweep",
    }
