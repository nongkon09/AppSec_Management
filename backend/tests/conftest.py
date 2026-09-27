import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
# Never reach Dependency-Track or public threat-intel feeds from the test suite, even when
# it runs inside a container whose environment points at live ones.
os.environ["DEPENDENCY_TRACK_API_KEY"] = ""
os.environ["DEPENDENCY_TRACK_UPLOAD_API_KEY"] = ""
os.environ["CISA_KEV_FEED_URL"] = ""
os.environ["EPSS_API_URL"] = ""
os.environ["OSV_API_URL"] = ""
os.environ["SBOM_EVIDENCE_DIR"] = "/tmp/appsec-test-sbom-evidence"

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.db import Base, get_db
from app.core.security import hash_password
from app.main import app
from app.models.component import Component
from app.models.finding import Finding, FindingSource, FindingStatus, SeverityTier
from app.models.inventory import Application, AppType, AppVersion, Criticality, Environment
from app.models.pentest import EngagementType, PentestProject, PentestStatus
from app.models.user import ApprovalLevel, Role, User

TEST_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture(autouse=True)
def _fresh_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def _override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db


@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def make_user(db_session):
    def _make_user(
        username: str,
        role: Role,
        owner_team: str | None = None,
        password: str = "Passw0rd!",
        approval_level: ApprovalLevel = ApprovalLevel.NONE,
    ):
        user = User(
            username=username,
            email=f"{username}@example.local",
            full_name=username,
            hashed_password=hash_password(password),
            role=role,
            owner_team=owner_team,
            approval_level=approval_level,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        return user

    return _make_user


@pytest.fixture
def make_application(db_session):
    def _make_application(
        app_name: str = "Payment Gateway",
        owner_team: str = "Team Alpha",
        app_type: AppType = AppType.IN_HOUSE,
        criticality: Criticality = Criticality.CRITICAL,
    ) -> Application:
        application = Application(
            app_name=app_name,
            app_type=app_type,
            owner_team=owner_team,
            criticality=criticality,
            environment=Environment.PRODUCTION,
        )
        db_session.add(application)
        db_session.commit()
        db_session.refresh(application)
        return application

    return _make_application


@pytest.fixture
def make_version(db_session):
    def _make_version(application: Application, version_label: str = "1.0.0") -> AppVersion:
        version = AppVersion(
            application_id=application.id,
            version_label=version_label,
            environment=Environment.PRODUCTION,
            is_current_production=True,
            is_active=True,
        )
        db_session.add(version)
        db_session.commit()
        db_session.refresh(version)
        return version

    return _make_version


@pytest.fixture
def make_component(db_session):
    def _make_component(
        version: AppVersion,
        component_name: str = "org.apache.logging.log4j:log4j-core",
        component_version: str = "2.14.1",
        scope: str = "production",
    ) -> Component:
        component = Component(
            app_version_id=version.id,
            component_name=component_name,
            version=component_version,
            scope=scope,
        )
        db_session.add(component)
        db_session.commit()
        db_session.refresh(component)
        return component

    return _make_component


@pytest.fixture
def make_finding(db_session):
    """Insert a Finding directly, bypassing the policy engine, so backlog/query tests can
    pin exact severity tiers and due dates."""

    def _make_finding(
        version: AppVersion,
        *,
        component: Component | None = None,
        severity_tier: SeverityTier = SeverityTier.CRITICAL,
        status: FindingStatus = FindingStatus.OPEN,
        source: FindingSource = FindingSource.SBOM,
        cve_id: str | None = "CVE-2021-44228",
        title: str | None = None,
        due_date=None,
        cvss: float | None = 10.0,
        epss: float | None = 0.97,
        kev_flag: bool = True,
        sla_started_on=None,
    ) -> Finding:
        finding = Finding(
            sla_started_on=sla_started_on,
            app_version_id=version.id,
            component_id=component.id if component else None,
            severity_tier=severity_tier,
            status=status,
            source=source,
            cve_id=cve_id,
            title=title,
            due_date=due_date,
            cvss=cvss,
            epss=epss,
            kev_flag=kev_flag,
            first_detected_at=datetime.now(UTC),
        )
        db_session.add(finding)
        db_session.commit()
        db_session.refresh(finding)
        return finding

    return _make_finding


@pytest.fixture
def make_pentest_project(db_session):
    """Defaults to `report_final` — the state from which a Pentest Finding may be
    attached (FR-6.5.6) — since that is what most tests need."""

    def _make_pentest_project(
        version: AppVersion,
        *,
        status: PentestStatus = PentestStatus.REPORT_FINAL,
        engagement_type: EngagementType = EngagementType.INTERNAL,
        vendor_name: str | None = None,
    ) -> PentestProject:
        project = PentestProject(
            app_version_id=version.id,
            status=status,
            engagement_type=engagement_type,
            vendor_name=vendor_name,
        )
        db_session.add(project)
        db_session.commit()
        db_session.refresh(project)
        return project

    return _make_pentest_project


@pytest.fixture
def auth_headers(client):
    def _auth_headers(username: str, password: str = "Passw0rd!"):
        resp = client.post("/api/v1/auth/login", data={"username": username, "password": password})
        assert resp.status_code == 200, resp.text
        token = resp.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    return _auth_headers
