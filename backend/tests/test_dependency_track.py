"""Dependency-Track connector mapping and threat-intel enrichment.

Response bodies mirror what Dependency-Track 4.14 actually returns for purl-only SBOMs:
advisories come from OSV/GitHub with a GHSA `vulnId`, a CVSS vector but no numeric score,
CVE IDs only under `aliases`, and CycloneDX properties split into groupName/propertyName.
"""

import httpx
import pytest

from app.integrations.cvss import base_score_from_vector
from app.integrations.dependency_track import DependencyTrackConnector
from app.integrations.sca_connector import SCAComponent, SCAFinding, SCAProject
from app.models.finding import Finding, SeverityTier
from app.modules.sbom import service
from tests.test_sbom import FakeConnector


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # log4shell
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_v3_base_score_from_vector(vector, expected):
    assert base_score_from_vector(vector) == expected


@pytest.mark.parametrize(
    "vector",
    [None, "", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSS:3.1/AV:N"],
)
def test_cvss_returns_none_for_unscorable_vectors(vector):
    assert base_score_from_vector(vector) is None


PROJECT_UUID = "11111111-1111-1111-1111-111111111111"


def _dt_transport(requests_seen: list[str]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        requests_seen.append(request.url.path)
        path = request.url.path
        if path == "/api/v1/project":
            return httpx.Response(
                200,
                json=[
                    {"uuid": PROJECT_UUID, "name": "Payment Gateway API", "version": "2026.10.0"}
                ],
            )
        if path == f"/api/v1/component/project/{PROJECT_UUID}":
            return httpx.Response(
                200,
                json=[
                    {
                        "uuid": "c-log4j",
                        "name": "log4j-core",
                        "version": "2.14.1",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                        "resolvedLicense": {"licenseId": "Apache-2.0"},
                    },
                    {
                        "uuid": "c-minimist",
                        "name": "minimist",
                        "version": "1.2.5",
                        "purl": "pkg:npm/minimist@1.2.5",
                    },
                ],
            )
        if path == "/api/v1/component/c-minimist/property":
            return httpx.Response(
                200,
                json=[
                    {
                        "groupName": "cdx",
                        "propertyName": "npm:package:development",
                        "propertyValue": "true",
                    }
                ],
            )
        if path == f"/api/v1/finding/project/{PROJECT_UUID}":
            log4j = {
                "name": "log4j-core",
                "version": "2.14.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            }
            return httpx.Response(
                200,
                json=[
                    {
                        "component": log4j,
                        "vulnerability": {
                            "vulnId": "GHSA-jfh8-c2jp-5v3q",
                            "source": "GITHUB",
                            "severity": "CRITICAL",
                            "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            "aliases": [
                                {"cveId": "CVE-2021-44228", "ghsaId": "GHSA-jfh8-c2jp-5v3q"}
                            ],
                        },
                        "analysis": {"isSuppressed": False},
                    },
                    {
                        # The same CVE again via NVD, with a lower score: must merge, not duplicate.
                        "component": log4j,
                        "vulnerability": {
                            "vulnId": "CVE-2021-44228",
                            "source": "NVD",
                            "cvssV3BaseScore": 9.0,
                            "epssScore": 0.94,
                        },
                        "analysis": {},
                    },
                    {
                        "component": log4j,
                        "vulnerability": {
                            "vulnId": "GHSA-7rjr-3q55-vv33",
                            "source": "GITHUB",
                            "cvssV3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            "aliases": [],
                        },
                        "analysis": {},
                    },
                    {
                        "component": log4j,
                        "vulnerability": {"vulnId": "GHSA-suppressed-0000", "cvssV3BaseScore": 5.0},
                        "analysis": {"isSuppressed": True},
                    },
                ],
            )
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _connector(requests_seen: list[str]) -> DependencyTrackConnector:
    return DependencyTrackConnector(
        base_url="http://dt.test",
        api_key="read-key",
        upload_api_key="upload-key",
        transport=_dt_transport(requests_seen),
    )


class TestDependencyTrackConnector:
    def test_components_read_dev_scope_from_property_endpoint(self):
        seen: list[str] = []
        components = {c.name: c for c in _connector(seen).get_components(PROJECT_UUID)}

        assert components["minimist"].scope == "development"
        assert components["log4j-core"].scope == "production"
        assert components["log4j-core"].license == "Apache-2.0"
        # Properties are only fetched for ecosystems whose generators emit them.
        assert "/api/v1/component/c-log4j/property" not in seen

    def test_findings_resolve_cve_compute_cvss_and_merge_duplicates(self):
        findings = {f.cve_id: f for f in _connector([]).get_findings(PROJECT_UUID)}

        assert set(findings) == {"CVE-2021-44228", "GHSA-7rjr-3q55-vv33"}
        log4shell = findings["CVE-2021-44228"]
        assert log4shell.cvss == 10.0  # computed from the GHSA vector, beats NVD's 9.0
        assert log4shell.epss == 0.94  # only the NVD record carried EPSS
        assert findings["GHSA-7rjr-3q55-vv33"].cvss == 9.0

    def test_upload_uses_the_separate_upload_key(self):
        keys: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            keys.append(request.headers.get("X-Api-Key"))
            return httpx.Response(200, json={"token": "t"})

        connector = DependencyTrackConnector(
            base_url="http://dt.test",
            api_key="read-key",
            upload_api_key="upload-key",
            transport=httpx.MockTransport(handler),
        )
        connector.upload_bom("App", "1.0.0", b"{}")
        assert keys == ["upload-key"]


class FakeThreatIntel:
    def __init__(
        self,
        kev: set[str],
        epss: dict[str, float],
        aliases: dict[str, tuple[str, ...]] | None = None,
    ):
        self._kev = kev
        self._epss = epss
        self._aliases = aliases or {}
        self.epss_requests: list[list[str]] = []

    def is_kev(self, cve_id: str) -> bool:
        return cve_id in self._kev

    def epss_scores(self, cve_ids):
        ids = list(cve_ids)
        self.epss_requests.append(ids)
        return {cve: self._epss[cve] for cve in ids if cve in self._epss}

    def cve_aliases(self, advisory_ids):
        return {i: self._aliases[i] for i in advisory_ids if i in self._aliases}


class TestThreatIntelEnrichment:
    def _sync_all(self, db_session, findings: list[SCAFinding], intel: FakeThreatIntel):
        component = SCAComponent(
            name="log4j-core", version="2.14.1", license=None, purl=None, scope="production"
        )
        connector = FakeConnector(
            projects=[SCAProject(external_id="p1", name="Payment Gateway API", version="1.0.0")],
            components={"p1": [component]},
            findings={"p1": findings},
        )
        service.sync_from_connector(db_session, connector=connector, threat_intel=intel)
        return db_session.query(Finding).all()

    def _sync(self, db_session, finding: SCAFinding, intel: FakeThreatIntel):
        [stored] = self._sync_all(db_session, [finding], intel)
        return stored

    def test_advisories_for_the_same_cve_become_one_finding(self, db_session):
        """Two GHSA advisories that OSV maps to one CVE: one finding, keyed by the CVE,
        with the higher score and the CVE's KEV listing applied."""

        def advisory(advisory_id: str, cvss: float) -> SCAFinding:
            return SCAFinding(
                component_purl=None,
                component_name="log4j-core",
                component_version="2.14.1",
                cve_id=advisory_id,
                cvss=cvss,
                epss=None,
                kev_flag=False,
            )

        intel = FakeThreatIntel(
            kev={"CVE-2021-44228"},
            epss={},
            aliases={"GHSA-jfh8-c2jp-5v3q": ("CVE-2021-44228",), "GHSA-dup": ("CVE-2021-44228",)},
        )
        stored = self._sync_all(
            db_session, [advisory("GHSA-jfh8-c2jp-5v3q", 10.0), advisory("GHSA-dup", 7.5)], intel
        )

        assert [(f.cve_id, f.cvss, f.kev_flag) for f in stored] == [("CVE-2021-44228", 10.0, True)]

    def test_kev_listing_forces_critical_even_with_moderate_cvss(self, db_session):
        finding = SCAFinding(
            component_purl=None,
            component_name="log4j-core",
            component_version="2.14.1",
            cve_id="CVE-2021-44228",
            cvss=5.0,
            epss=None,
            kev_flag=False,
        )
        intel = FakeThreatIntel(kev={"CVE-2021-44228"}, epss={"CVE-2021-44228": 0.97})

        stored = self._sync(db_session, finding, intel)

        assert stored.kev_flag is True
        assert stored.epss == pytest.approx(0.97)
        assert stored.severity_tier == SeverityTier.CRITICAL

    def test_platform_epss_is_kept_and_not_looked_up_again(self, db_session):
        finding = SCAFinding(
            component_purl=None,
            component_name="log4j-core",
            component_version="2.14.1",
            cve_id="CVE-2020-0001",
            cvss=5.0,
            epss=0.12,
            kev_flag=False,
        )
        intel = FakeThreatIntel(kev=set(), epss={"CVE-2020-0001": 0.99})

        stored = self._sync(db_session, finding, intel)

        assert stored.epss == pytest.approx(0.12)
        assert intel.epss_requests == []

    def test_advisory_citing_several_cves_keeps_its_id_but_inherits_signals(self, db_session):
        """A regression advisory that cites the old CVE and a new one must not be labelled
        as the old CVE; KEV/EPSS still come from both."""
        finding = SCAFinding(
            component_purl=None,
            component_name="log4j-core",
            component_version="2.14.1",
            cve_id="GHSA-r5fr-rjxr-66jc",
            cvss=5.0,
            epss=None,
            kev_flag=False,
        )
        intel = FakeThreatIntel(
            kev={"CVE-2021-23337"},
            epss={"CVE-2021-23337": 0.4, "CVE-2026-4800": 0.02},
            aliases={"GHSA-r5fr-rjxr-66jc": ("CVE-2021-23337", "CVE-2026-4800")},
        )

        stored = self._sync(db_session, finding, intel)

        assert stored.cve_id == "GHSA-r5fr-rjxr-66jc"
        assert stored.kev_flag is True
        assert stored.epss == pytest.approx(0.4)
