"""SBOM ingestion tests (Requirement.md FR-2, FR-3).

The Dependency-Track pull-sync (FR-2.5/FR-3) is tested against a `FakeConnector` rather
than a live Dependency-Track instance — exactly the point of the `SCAConnector` interface
(FR-2.5's "Integration Layer"): the reconciliation logic (auto-create, upsert, re-tier,
auto-close) is independent of which SCA platform supplies the data, and is fully testable
without one running. The manual upload path (FR-2.6) needs no external service at all and
is tested end-to-end through the real HTTP API.
"""

import json
from datetime import UTC, datetime, timedelta

import pytest

from app.integrations.sca_connector import SCAComponent, SCAFinding, SCAProject
from app.models.finding import Finding, FindingStatus
from app.models.inventory import Application, AppVersion
from app.models.user import Role
from app.modules.sbom import service
from app.modules.sbom.parser import SbomFormatError, parse_sbom

# --- Fixtures: sample SBOM documents -----------------------------------------------


def _cyclonedx_bytes(*, log4j_version: str = "2.14.1", include_lodash: bool = True) -> bytes:
    components = [
        {
            "type": "library",
            "group": "org.apache.logging.log4j",
            "name": "log4j-core",
            "version": log4j_version,
            "purl": f"pkg:maven/org.apache.logging.log4j/log4j-core@{log4j_version}",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        }
    ]
    if include_lodash:
        components.append(
            {
                "type": "library",
                "name": "eslint-plugin-test",
                "version": "1.0.0",
                "purl": "pkg:npm/eslint-plugin-test@1.0.0",
                "scope": "optional",  # FR-4.2: dev-only dependency
                "licenses": [{"license": {"name": "MIT"}}],
            }
        )
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": components,
        }
    ).encode()


def _spdx_bytes() -> bytes:
    return json.dumps(
        {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "requests",
                    "versionInfo": "2.25.0",
                    "licenseConcluded": "Apache-2.0",
                    "externalRefs": [
                        {
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/requests@2.25.0",
                        }
                    ],
                }
            ],
        }
    ).encode()


# --- Parser --------------------------------------------------------------------------


class TestSbomParser:
    def test_parses_cyclonedx_components(self):
        parsed = parse_sbom(_cyclonedx_bytes())
        assert parsed.sbom_format == "cyclonedx"
        by_name = {c.name: c for c in parsed.components}
        log4j = by_name["org.apache.logging.log4j:log4j-core"]
        assert log4j.version == "2.14.1"
        assert log4j.license == "Apache-2.0"
        assert log4j.scope == "production"

    def test_cyclonedx_optional_scope_maps_to_development(self):
        """FR-4.2: an 'optional' CycloneDX scope is a dev-only dependency."""
        parsed = parse_sbom(_cyclonedx_bytes())
        dev_component = next(c for c in parsed.components if "eslint" in c.name)
        assert dev_component.scope == "development"

    def test_parses_spdx_packages(self):
        parsed = parse_sbom(_spdx_bytes())
        assert parsed.sbom_format == "spdx"
        assert len(parsed.components) == 1
        package = parsed.components[0]
        assert package.name == "requests"
        assert package.license == "Apache-2.0"
        assert package.purl == "pkg:pypi/requests@2.25.0"

    def test_rejects_invalid_json(self):
        with pytest.raises(SbomFormatError, match="not valid JSON"):
            parse_sbom(b"not json at all {")

    def test_rejects_unrecognized_document(self):
        with pytest.raises(SbomFormatError, match="Unrecognized SBOM format"):
            parse_sbom(json.dumps({"hello": "world"}).encode())

    def test_rejects_json_array(self):
        with pytest.raises(SbomFormatError, match="JSON object"):
            parse_sbom(b"[1, 2, 3]")


# --- Manual upload (FR-2.6) — real HTTP, no external service needed -----------------


class TestManualUpload:
    def _upload(self, client, headers, application_id, version_label="1.0.0", body=None):
        return client.post(
            "/api/v1/sbom/upload",
            headers=headers,
            data={"application_id": str(application_id), "version_label": version_label},
            files={"file": ("bom.json", body or _cyclonedx_bytes(), "application/json")},
        )

    def test_appsec_uploads_cyclonedx(self, client, make_user, auth_headers, make_application):
        application = make_application()
        make_user("appsec.lead", Role.APPSEC)
        resp = self._upload(client, auth_headers("appsec.lead"), application.id)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["sbom_format"] == "cyclonedx"
        assert body["components_ingested"] == 2
        # No Dependency-Track configured in tests -> no forward attempted.
        assert body["forwarded_to_sca_platform"] is False
        assert body["forward_error"] is None

    def test_dev_team_cannot_upload(self, client, make_user, auth_headers, make_application):
        application = make_application(owner_team="Team Alpha")
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        resp = self._upload(client, auth_headers("dev.alpha"), application.id)
        assert resp.status_code == 403

    def test_invalid_format_returns_422(self, client, make_user, auth_headers, make_application):
        application = make_application()
        make_user("appsec.lead", Role.APPSEC)
        resp = self._upload(client, auth_headers("appsec.lead"), application.id, body=b"{}")
        assert resp.status_code == 422

    def test_unknown_application_returns_404(self, client, make_user, auth_headers):
        make_user("appsec.lead", Role.APPSEC)
        resp = self._upload(
            client, auth_headers("appsec.lead"), "00000000-0000-0000-0000-000000000000"
        )
        assert resp.status_code == 404

    def test_reupload_to_same_version_upserts_without_duplicating(
        self, client, make_user, auth_headers, make_application, db_session
    ):
        """FR-2.6.1 uploads into the same Application/Version repeatedly (e.g. a vendor
        re-sends a corrected SBOM) must not accumulate duplicate Components."""
        application = make_application()
        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")

        self._upload(client, headers, application.id, body=_cyclonedx_bytes(log4j_version="2.14.1"))
        second = self._upload(
            client, headers, application.id, body=_cyclonedx_bytes(log4j_version="2.17.1")
        )
        assert second.status_code == 201
        assert second.json()["components_ingested"] == 2

        version = db_session.query(AppVersion).filter_by(application_id=application.id).one()
        from app.models.component import Component

        components = db_session.query(Component).filter_by(app_version_id=version.id).all()
        assert len(components) == 2  # updated in place, not duplicated
        log4j = next(c for c in components if "log4j" in c.component_name)
        assert log4j.version == "2.17.1"

    def test_upload_records_ingestion_history(
        self, client, make_user, auth_headers, make_application, db_session
    ):
        application = make_application()
        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")
        self._upload(client, headers, application.id)

        version = db_session.query(AppVersion).filter_by(application_id=application.id).one()
        history = client.get(
            "/api/v1/sbom/ingestion-history",
            headers=headers,
            params={"app_version_id": str(version.id)},
        )
        assert history.status_code == 200
        rows = history.json()
        assert len(rows) == 1
        assert rows[0]["is_manual_upload"] is True
        assert rows[0]["uploaded_by"] == "appsec.lead"
        assert rows[0]["scan_type"] == "sbom"

    def test_upload_marks_version_ingested_and_not_stale(
        self, client, make_user, auth_headers, make_application, db_session
    ):
        application = make_application()
        make_user("appsec.lead", Role.APPSEC)
        self._upload(client, auth_headers("appsec.lead"), application.id)

        version = db_session.query(AppVersion).filter_by(application_id=application.id).one()
        db_session.refresh(version)
        assert version.last_ingested_at is not None
        assert version.is_stale is False


class TestSyncRbac:
    """The happy path of an actual sync is covered in TestDependencyTrackSync via the
    service layer + FakeConnector; this only checks that RBAC is enforced before any
    network call to the SCA platform would be attempted."""

    def test_dev_team_cannot_trigger_sync(self, client, make_user, auth_headers):
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        resp = client.post("/api/v1/sbom/sync", headers=auth_headers("dev.alpha"))
        assert resp.status_code == 403

    def test_dev_team_cannot_trigger_stale_check(self, client, make_user, auth_headers):
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        resp = client.post("/api/v1/sbom/stale-check", headers=auth_headers("dev.alpha"))
        assert resp.status_code == 403

    def test_anonymous_cannot_trigger_sync(self, client):
        assert client.post("/api/v1/sbom/sync").status_code == 401


# --- Dependency-Track pull-sync (FR-2.5, FR-3) — service layer + FakeConnector -------


class FakeConnector:
    """A minimal `SCAConnector` double: exactly what `sync_from_connector` needs, with
    no HTTP client and no live Dependency-Track instance."""

    def __init__(
        self,
        projects: list[SCAProject],
        components: dict[str, list[SCAComponent]],
        findings: dict[str, list[SCAFinding]],
    ):
        self._projects = projects
        self._components = components
        self._findings = findings

    def list_projects(self) -> list[SCAProject]:
        return self._projects

    def get_components(self, project_external_id: str) -> list[SCAComponent]:
        return self._components.get(project_external_id, [])

    def get_findings(self, project_external_id: str) -> list[SCAFinding]:
        return self._findings.get(project_external_id, [])

    def upload_bom(self, project_name: str, project_version: str, bom_bytes: bytes) -> None:
        raise NotImplementedError("not exercised by the pull-sync tests")


LOG4J_COMPONENT = SCAComponent(
    name="log4j-core",
    version="2.14.1",
    license="Apache-2.0",
    purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    scope="production",
)
LOG4J_KEV_FINDING = SCAFinding(
    component_purl=LOG4J_COMPONENT.purl,
    component_name=LOG4J_COMPONENT.name,
    component_version=LOG4J_COMPONENT.version,
    cve_id="CVE-2021-44228",
    cvss=10.0,
    epss=0.97,
    kev_flag=True,
)


class TestDependencyTrackSync:
    def test_sync_auto_creates_application_and_version(self, db_session):
        """FR-1.5: an unregistered project seen from the SCA platform is auto-created,
        with ownership left unconfirmed for AppSec to assign later."""
        connector = FakeConnector(
            projects=[
                SCAProject(external_id="p1", name="Customer Web Portal", version="1.0.0")
            ],
            components={"p1": [LOG4J_COMPONENT]},
            findings={"p1": [LOG4J_KEV_FINDING]},
        )
        result = service.sync_from_connector(db_session, connector=connector)

        assert result.projects_seen == 1
        assert result.applications_auto_created == 1
        assert result.components_upserted == 1
        assert result.findings_created == 1
        assert not result.errors

        application = (
            db_session.query(Application).filter_by(app_name="Customer Web Portal").one()
        )
        assert application.ownership_confirmed is False

    def test_finding_severity_comes_from_policy_engine(self, db_session):
        """FR-4.1: KEV=True must tier as Critical regardless of the raw CVSS band that
        (hypothetically) would otherwise map lower."""
        connector = FakeConnector(
            projects=[SCAProject(external_id="p1", name="App A", version="1.0.0")],
            components={"p1": [LOG4J_COMPONENT]},
            findings={"p1": [LOG4J_KEV_FINDING]},
        )
        service.sync_from_connector(db_session, connector=connector)

        finding = db_session.query(Finding).filter_by(cve_id="CVE-2021-44228").one()
        assert finding.severity_tier == "critical"
        assert finding.due_date is not None  # Critical => 7-day SLA under the default policy
        assert finding.policy_version == 1

    def test_resync_is_idempotent(self, db_session):
        """Running the same sync twice must not create duplicate Components or Findings."""
        connector = FakeConnector(
            projects=[SCAProject(external_id="p1", name="App A", version="1.0.0")],
            components={"p1": [LOG4J_COMPONENT]},
            findings={"p1": [LOG4J_KEV_FINDING]},
        )
        service.sync_from_connector(db_session, connector=connector)
        second = service.sync_from_connector(db_session, connector=connector)

        assert second.applications_auto_created == 0  # already exists on the 2nd run
        assert second.findings_created == 0  # already exists -> updated, not recreated
        assert db_session.query(Finding).filter_by(cve_id="CVE-2021-44228").count() == 1

    def test_finding_resolved_upstream_is_auto_closed(self, db_session):
        """FR-3.2: 'delta matching ... โดยไม่ต้องรอ Rebuild/Redeploy' — once the SCA
        platform stops reporting a CVE for a component, our Finding must close on the
        very next sync, with no rebuild involved."""
        connector = FakeConnector(
            projects=[SCAProject(external_id="p1", name="App A", version="1.0.0")],
            components={"p1": [LOG4J_COMPONENT]},
            findings={"p1": [LOG4J_KEV_FINDING]},
        )
        service.sync_from_connector(db_session, connector=connector)

        # Second sync: the CVE is gone (component was upgraded upstream in Dependency-Track).
        connector._findings["p1"] = []
        result = service.sync_from_connector(db_session, connector=connector)

        assert result.findings_auto_closed == 1
        finding = db_session.query(Finding).filter_by(cve_id="CVE-2021-44228").one()
        assert finding.status == FindingStatus.FIXED
        assert finding.fixed_at is not None

    def test_reintroduced_finding_reopens_instead_of_duplicating(self, db_session):
        connector = FakeConnector(
            projects=[SCAProject(external_id="p1", name="App A", version="1.0.0")],
            components={"p1": [LOG4J_COMPONENT]},
            findings={"p1": [LOG4J_KEV_FINDING]},
        )
        service.sync_from_connector(db_session, connector=connector)
        connector._findings["p1"] = []
        service.sync_from_connector(db_session, connector=connector)  # closes it
        connector._findings["p1"] = [LOG4J_KEV_FINDING]
        service.sync_from_connector(db_session, connector=connector)  # reappears

        findings = db_session.query(Finding).filter_by(cve_id="CVE-2021-44228").all()
        assert len(findings) == 1
        assert findings[0].status == FindingStatus.OPEN
        assert findings[0].fixed_at is None

    def test_dev_scope_component_downgrades_severity(self, db_session):
        """FR-4.2: a development-only dependency is de-prioritised even when synced
        from the SCA platform, not just on manual Finding creation."""
        dev_component = SCAComponent(
            name="eslint-utils",
            version="1.4.0",
            license="MIT",
            purl="pkg:npm/eslint-utils@1.4.0",
            scope="development",
        )
        finding = SCAFinding(
            component_purl=dev_component.purl,
            component_name=dev_component.name,
            component_version=dev_component.version,
            cve_id="CVE-2020-7598",
            cvss=7.5,
            epss=0.0,
            kev_flag=False,
        )
        connector = FakeConnector(
            projects=[SCAProject(external_id="p1", name="App A", version="1.0.0")],
            components={"p1": [dev_component]},
            findings={"p1": [finding]},
        )
        service.sync_from_connector(db_session, connector=connector)

        row = db_session.query(Finding).filter_by(cve_id="CVE-2020-7598").one()
        # CVSS 7.5 alone -> High, but development scope downgrades one tier -> Medium.
        assert row.severity_tier == "medium"

    def test_existing_application_is_reused_not_duplicated(self, db_session, make_application):
        """A project matching an already-registered Application must attach to it
        rather than creating a second Application with the same name."""
        application = make_application(app_name="Payment Gateway API", owner_team="Team Alpha")
        connector = FakeConnector(
            projects=[SCAProject(external_id="p1", name="Payment Gateway API", version="2.0.0")],
            components={"p1": [LOG4J_COMPONENT]},
            findings={"p1": []},
        )
        result = service.sync_from_connector(db_session, connector=connector)

        assert result.applications_auto_created == 0
        assert db_session.query(Application).filter_by(app_name="Payment Gateway API").count() == 1
        version = db_session.query(AppVersion).filter_by(application_id=application.id).one()
        assert version.version_label == "2.0.0"

    def test_one_project_failure_does_not_abort_the_whole_sync(self, db_session):
        """A single malformed project must not prevent the rest of the sync from
        completing — errors are collected, not raised."""

        class ExplodingConnector(FakeConnector):
            def get_components(self, project_external_id: str) -> list[SCAComponent]:
                if project_external_id == "broken":
                    raise RuntimeError("simulated upstream failure")
                return super().get_components(project_external_id)

        connector = ExplodingConnector(
            projects=[
                SCAProject(external_id="broken", name="Broken App", version="1.0.0"),
                SCAProject(external_id="p1", name="Healthy App", version="1.0.0"),
            ],
            components={"p1": [LOG4J_COMPONENT]},
            findings={"p1": [LOG4J_KEV_FINDING]},
        )
        result = service.sync_from_connector(db_session, connector=connector)

        assert result.projects_seen == 2
        assert len(result.errors) == 1
        assert "Broken App" in result.errors[0]
        # The healthy project still went through.
        assert db_session.query(Application).filter_by(app_name="Healthy App").count() == 1
        assert db_session.query(Application).filter_by(app_name="Broken App").count() == 0


# --- Staleness sweep (FR-2.4) ---------------------------------------------------------


class TestStaleCheck:
    def test_never_ingested_version_becomes_stale_after_threshold(
        self, db_session, make_application, make_version
    ):
        application = make_application()
        version = make_version(application)
        # Simulate a version registered long before it was ever scanned.
        version.created_at = datetime.now(UTC) - timedelta(days=100)
        db_session.commit()

        result = service.check_stale_versions(db_session, threshold_days=90)

        assert version.id in result.newly_flagged_version_ids
        db_session.refresh(version)
        assert version.is_stale is True

    def test_recently_ingested_version_is_not_stale(
        self, db_session, make_application, make_version
    ):
        application = make_application()
        version = make_version(application)
        version.last_ingested_at = datetime.now(UTC) - timedelta(days=5)
        db_session.commit()

        result = service.check_stale_versions(db_session, threshold_days=90)

        assert version.id not in result.newly_flagged_version_ids
        db_session.refresh(version)
        assert version.is_stale is False

    def test_old_ingest_crosses_threshold(self, db_session, make_application, make_version):
        application = make_application()
        version = make_version(application)
        version.last_ingested_at = datetime.now(UTC) - timedelta(days=95)
        db_session.commit()

        service.check_stale_versions(db_session, threshold_days=90)

        db_session.refresh(version)
        assert version.is_stale is True

    def test_already_stale_version_is_not_recounted_as_newly_flagged(
        self, db_session, make_application, make_version
    ):
        application = make_application()
        version = make_version(application)
        version.is_stale = True
        version.last_ingested_at = datetime.now(UTC) - timedelta(days=200)
        db_session.commit()

        result = service.check_stale_versions(db_session, threshold_days=90)

        assert version.id not in result.newly_flagged_version_ids
        assert result.total_stale_versions == 1

    def test_endpoint_triggers_stale_check(
        self, client, make_user, auth_headers, make_application, make_version, db_session
    ):
        application = make_application()
        version = make_version(application)
        version.created_at = datetime.now(UTC) - timedelta(days=100)
        db_session.commit()

        make_user("appsec.lead", Role.APPSEC)
        resp = client.post("/api/v1/sbom/stale-check", headers=auth_headers("appsec.lead"))
        assert resp.status_code == 200
        assert resp.json()["total_stale_versions"] == 1
