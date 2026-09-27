"""SLA anchoring, sync status preservation, active versions and deployments
(docs/risk-exception-design.md 3.2-3.3, gaps G1-G3)."""

from datetime import UTC, datetime, timedelta

import pytest

from app.integrations.sca_connector import SCAComponent, SCAFinding, SCAProject
from app.models.finding import Finding, FindingStatus
from app.models.inventory import AppVersion
from app.models.user import Role
from app.modules.policy import service as policy_service
from app.modules.sbom import service as sbom_service
from tests.test_dependency_track import FakeThreatIntel
from tests.test_sbom import FakeConnector

TODAY = datetime.now(UTC).date()
PURL = "pkg:npm/lodash@4.17.20"


def _connector(version_label: str, *, include_vuln: bool = True, project_id: str | None = None):
    pid = project_id or f"p-{version_label}"
    component = SCAComponent(
        name="lodash", version="4.17.20", license="MIT", purl=PURL, scope="production"
    )
    finding = SCAFinding(
        component_purl=PURL,
        component_name="lodash",
        component_version="4.17.20",
        cve_id="CVE-2021-23337",
        cvss=7.2,
        epss=0.01,
        kev_flag=False,
    )
    return FakeConnector(
        projects=[SCAProject(external_id=pid, name="Shop API", version=version_label)],
        components={pid: [component]},
        findings={pid: [finding] if include_vuln else []},
    )


def _sync(db, version_label: str, **kwargs):
    return sbom_service.sync_from_connector(
        db,
        connector=_connector(version_label, **kwargs),
        threat_intel=FakeThreatIntel(kev=set(), epss={}),
    )


def _rows(db, version_label: str) -> list[Finding]:
    return (
        db.query(Finding)
        .join(AppVersion, Finding.app_version_id == AppVersion.id)
        .filter(AppVersion.version_label == version_label)
        .all()
    )


class TestSyncBugs:
    def test_decided_status_survives_a_resync(self, db_session):
        """G11: a risk-accepted or suppressed finding used to be reopened by the next sync."""
        _sync(db_session, "1.0.0")
        [finding] = _rows(db_session, "1.0.0")
        finding.status = FindingStatus.RISK_ACCEPTED
        db_session.commit()

        _sync(db_session, "1.0.0")
        db_session.refresh(finding)
        assert finding.status == FindingStatus.RISK_ACCEPTED

    def test_due_date_does_not_slide_on_every_sync(self, db_session):
        """G1: the due date used to be recomputed as today + SLA on each sync."""
        _sync(db_session, "1.0.0")
        [finding] = _rows(db_session, "1.0.0")
        finding.sla_started_on = TODAY - timedelta(days=40)
        db_session.commit()

        _sync(db_session, "1.0.0")
        db_session.refresh(finding)
        policy = policy_service.get_effective_policy(db_session)
        assert finding.due_date == policy_service.compute_due_date(
            policy, finding.severity_tier, TODAY - timedelta(days=40)
        )
        assert finding.due_date < TODAY  # genuinely overdue now


class TestSlaAnchor:
    def test_new_version_inherits_the_anchor(self, db_session):
        """G2: shipping a new build must not restart the SLA clock."""
        _sync(db_session, "1.0.0")
        [v1] = _rows(db_session, "1.0.0")
        v1.sla_started_on = TODAY - timedelta(days=12)
        db_session.commit()

        _sync(db_session, "1.1.0")
        [v2] = _rows(db_session, "1.1.0")
        assert v2.issue_key == v1.issue_key == "sbom:pkg:npm/lodash:cve-2021-23337"
        assert v2.sla_started_on == TODAY - timedelta(days=12)

    def test_reintroduction_after_a_real_fix_starts_a_new_clock(self, db_session):
        _sync(db_session, "1.0.0", project_id="p1")
        [finding] = _rows(db_session, "1.0.0")
        finding.sla_started_on = TODAY - timedelta(days=30)
        db_session.commit()

        _sync(db_session, "1.0.0", project_id="p1", include_vuln=False)
        db_session.refresh(finding)
        assert finding.status == FindingStatus.FIXED

        _sync(db_session, "1.0.0", project_id="p1")
        db_session.refresh(finding)
        assert finding.status == FindingStatus.OPEN
        assert finding.sla_started_on == TODAY


class TestActiveVersions:
    def test_latest_ingested_version_is_active_without_deployments(self, db_session):
        _sync(db_session, "1.0.0")
        _sync(db_session, "1.1.0")
        versions = {v.version_label: v.is_active for v in db_session.query(AppVersion).all()}
        assert versions == {"1.0.0": False, "1.1.0": True}

    def test_backlog_counts_active_versions_only(self, db_session, client, make_user, auth_headers):
        _sync(db_session, "1.0.0")
        _sync(db_session, "1.1.0")
        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")

        default = client.get("/api/v1/findings", headers=headers).json()
        assert [row["version_label"] for row in default["items"]] == ["1.1.0"]
        everything = client.get(
            "/api/v1/findings?include_inactive_versions=true", headers=headers
        ).json()
        assert everything["total"] == 2


@pytest.fixture
def shop(db_session, make_user):
    _sync(db_session, "1.0.0")
    make_user("appsec.lead", Role.APPSEC)
    make_user("ci.pipeline", Role.PIPELINE)
    make_user("dev.beta", Role.DEV_TEAM, owner_team="Team Beta")


class TestDeployments:
    def test_pipeline_records_by_name_and_replaces_previous(
        self, shop, client, auth_headers, db_session
    ):
        headers = auth_headers("ci.pipeline")
        first = client.post(
            "/api/v1/deployments",
            json={
                "application_name": "Shop API",
                "version_label": "1.0.0",
                "environment": "production",
                "image_digest": "sha256:aaa",
            },
            headers=headers,
        )
        assert first.status_code == 201 and first.json()["source"] == "pipeline"

        second = client.post(
            "/api/v1/deployments",
            json={
                "application_name": "Shop API",
                "version_label": "1.2.0",  # not scanned yet: created on the fly
                "environment": "production",
                "reference_url": "https://ci.example/run/7",
            },
            headers=headers,
        )
        assert second.status_code == 201

        listing = client.get(
            f"/api/v1/applications/{second.json()['application_id']}/deployments",
            headers=auth_headers("appsec.lead"),
        ).json()
        assert [(row["version_label"], row["ended_at"] is None) for row in listing] == [
            ("1.2.0", True),
            ("1.0.0", False),
        ]
        versions = {v.version_label: v.is_active for v in db_session.query(AppVersion).all()}
        assert versions == {"1.0.0": False, "1.2.0": True}

    def test_other_team_and_pipeline_reads_are_refused(self, shop, client, auth_headers):
        body = {"application_name": "Shop API", "version_label": "1.0.0", "environment": "staging"}
        assert (
            client.post(
                "/api/v1/deployments", json=body, headers=auth_headers("dev.beta")
            ).status_code
            == 404
        )
        created = client.post("/api/v1/deployments", json=body, headers=auth_headers("ci.pipeline"))
        app_id = created.json()["application_id"]
        assert (
            client.get(
                f"/api/v1/applications/{app_id}/deployments", headers=auth_headers("ci.pipeline")
            ).status_code
            == 403
        )

    def test_summary_counts_an_issue_once_across_active_versions(
        self, shop, client, auth_headers, db_session
    ):
        _sync(db_session, "1.1.0")
        headers = auth_headers("ci.pipeline")
        for label, env in (("1.0.0", "staging"), ("1.1.0", "production")):
            client.post(
                "/api/v1/deployments",
                json={"application_name": "Shop API", "version_label": label, "environment": env},
                headers=headers,
            )
        appsec = auth_headers("appsec.lead")
        rows = client.get("/api/v1/findings", headers=appsec).json()
        assert rows["total"] == 2  # one row per active version
        summary = client.get("/api/v1/findings/summary", headers=appsec).json()
        assert summary["total_open"] == 1  # one issue
