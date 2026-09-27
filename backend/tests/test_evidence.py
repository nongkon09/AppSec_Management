"""Scan snapshots and the Release Evidence Pack (docs/risk-exception-design.md 3.7, W7)."""

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from app.integrations.dependency_track import _evidence_from_tags
from app.integrations.sca_connector import SCAComponent, SCAFinding, SCAProject
from app.models.inventory import AppVersion
from app.models.scan_result import ScanFinding, ScanResult
from app.models.user import Role
from app.modules.sbom import service as sbom_service
from tests.test_dependency_track import FakeThreatIntel
from tests.test_sbom import FakeConnector

NOW = datetime.now(UTC)
PURL = "pkg:npm/lodash@4.17.20"


def test_pipeline_tags_become_evidence():
    tags = [
        {"name": "commit:9f2c1ab"},
        {"name": "digest:sha256-3b1f0c"},
        {"name": "tool:harbor"},
        {"name": "pipeline:1432"},
        {"name": "team-alpha"},
    ]
    assert _evidence_from_tags(tags) == {
        "commit": "9f2c1ab",
        "digest": "sha256:3b1f0c",
        "tool": "harbor",
        "pipeline": "1432",
    }


def _sync(db, *, imported_at, version="1.0.0", evidence=None):
    project = SCAProject(
        external_id="p1",
        name="Shop API",
        version=version,
        evidence=evidence or {},
        last_bom_import=imported_at,
    )
    connector = FakeConnector(
        projects=[project],
        components={
            "p1": [
                SCAComponent(
                    name="lodash", version="4.17.20", license="MIT", purl=PURL, scope="production"
                )
            ]
        },
        findings={
            "p1": [
                SCAFinding(
                    component_purl=PURL,
                    component_name="lodash",
                    component_version="4.17.20",
                    cve_id="CVE-2021-23337",
                    cvss=7.2,
                    epss=0.01,
                    kev_flag=False,
                )
            ]
        },
    )
    return sbom_service.sync_from_connector(
        db, connector=connector, threat_intel=FakeThreatIntel(kev=set(), epss={})
    )


class TestSnapshots:
    def test_snapshot_only_when_a_new_sbom_arrives(self, db_session):
        first_import = NOW - timedelta(hours=2)
        evidence = {"commit": "9f2c1ab", "digest": "sha256:3b1f0c", "tool": "harbor"}
        _sync(db_session, imported_at=first_import, evidence=evidence)
        _sync(db_session, imported_at=first_import, evidence=evidence)  # scheduled re-sync
        scans = db_session.query(ScanResult).all()
        assert len(scans) == 1
        scan = scans[0]
        assert (scan.source_tool, scan.image_digest, scan.commit_sha) == (
            "harbor",
            "sha256:3b1f0c",
            "9f2c1ab",
        )
        assert scan.sbom_sha256 and len(scan.sbom_sha256) == 64
        links = db_session.query(ScanFinding).filter_by(scan_result_id=scan.id).all()
        assert [(link.severity_tier, link.status) for link in links] == [("high", "open")]
        assert db_session.query(AppVersion).one().commit_sha == "9f2c1ab"

        _sync(db_session, imported_at=NOW, evidence=evidence)  # pipeline pushed again
        assert db_session.query(ScanResult).count() == 2


@pytest.fixture
def shop(db_session, make_user):
    _sync(
        db_session,
        imported_at=NOW - timedelta(days=40),
        evidence={"commit": "aaa111", "digest": "sha256:old"},
    )
    _sync(
        db_session,
        imported_at=NOW - timedelta(days=1),
        version="1.1.0",
        evidence={"commit": "bbb222", "digest": "sha256:new"},
    )
    make_user("appsec.lead", Role.APPSEC)
    make_user("audit.viewer", Role.AUDIT)
    make_user("ci.pipeline", Role.PIPELINE)
    make_user("dev.beta", Role.DEV_TEAM, owner_team="Team Beta")


class TestEvidencePack:
    def test_pack_shows_deployments_scans_and_baseline(self, shop, client, auth_headers):
        pipeline = auth_headers("ci.pipeline")
        old_deploy = (NOW - timedelta(days=35)).isoformat()
        for label, when in (("1.0.0", old_deploy), ("1.1.0", NOW.isoformat())):
            resp = client.post(
                "/api/v1/deployments",
                json={
                    "application_name": "Shop API",
                    "version_label": label,
                    "environment": "production",
                    "deployed_at": when,
                },
                headers=pipeline,
            )
            assert resp.status_code == 201, resp.text
        app_id = resp.json()["application_id"]

        date_from = (NOW - timedelta(days=7)).date().isoformat()
        pack = client.get(
            f"/api/v1/applications/{app_id}/evidence?date_from={date_from}",
            headers=auth_headers("audit.viewer"),
        )
        assert pack.status_code == 200, pack.text
        body = pack.json()
        assert [(d["version_label"], d["ended_at"] is None) for d in body["deployments"]] == [
            ("1.0.0", False),
            ("1.1.0", True),
        ]
        by_version = {s["version_label"]: s for s in body["scans"]}
        assert by_version["1.0.0"]["is_baseline"] is True  # scanned before the period
        assert by_version["1.1.0"]["is_baseline"] is False
        assert by_version["1.1.0"]["commit_sha"] == "bbb222"
        assert by_version["1.1.0"]["findings"][0]["label"] == "CVE-2021-23337"

        scan_id = by_version["1.1.0"]["id"]
        download = client.get(f"/api/v1/scans/{scan_id}/sbom", headers=auth_headers("appsec.lead"))
        assert download.status_code == 200
        assert hashlib.sha256(download.content).hexdigest() == by_version["1.1.0"]["sbom_sha256"]

    def test_pack_is_scoped(self, shop, client, auth_headers, db_session):
        app_id = db_session.query(AppVersion).first().application_id
        assert (
            client.get(
                f"/api/v1/applications/{app_id}/evidence", headers=auth_headers("dev.beta")
            ).status_code
            == 404
        )
        assert (
            client.get(
                f"/api/v1/applications/{app_id}/evidence", headers=auth_headers("ci.pipeline")
            ).status_code
            == 403
        )
