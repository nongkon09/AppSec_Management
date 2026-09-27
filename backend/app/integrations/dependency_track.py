"""OWASP Dependency-Track connector (Requirement.md FR-2.5, FR-2.7.4, FR-3.1).

Implements `SCAConnector` against Dependency-Track's v1 REST API. Authenticates with a
`X-Api-Key` header per FR-2.7 — the sync key (`settings.dependency_track_api_key`)
must be a **read-only** Service Account key, separate from the per-team/per-project keys
CI/CD pipelines use to push SBOM directly to Dependency-Track (FR-2.7.4); this platform
never receives that push (FR-2.7 confirmed).

Field mapping, verified against Dependency-Track 4.14:

- Findings matched through OSV/GitHub advisories carry `vulnId` = "GHSA-…" and only a CVSS
  *vector*; the numeric score is computed from it (`app.integrations.cvss`). The CVE ID
  comes from `aliases` when DT has them — 4.14 leaves them empty for the OSV mirror, so
  the sync service resolves the rest through OSV.dev (`app.integrations.threat_intel`).
- Several advisories can describe the same CVE for one component; they are merged into one
  finding keeping the highest scores.
- CycloneDX properties (e.g. `cdx:npm:package:development`) are not included in the
  component list and are fetched per component, only for ecosystems that use them.
- DT 4.x exposes no CISA KEV data; KEV/EPSS enrichment happens in the sync service
  (`app.integrations.threat_intel`), not here.
"""

import base64
import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from app.core.config import get_settings
from app.integrations.cvss import base_score_from_vector
from app.integrations.sca_connector import SCAComponent, SCAFinding, SCAProject, merge_findings

logger = logging.getLogger(__name__)

# CycloneDX/generator scope hints that indicate a dependency is development-only.
_DEV_SCOPE_MARKERS = {"optional", "excluded"}
_DEV_PROPERTY_NAMES = {
    "cdx:npm:package:development",
    "cdx:pip:package:development",
}


# Only these ecosystems' generators emit the development-dependency property, so only
# their components are worth an extra per-component properties request.
_PROPERTY_ECOSYSTEMS = ("pkg:npm/", "pkg:pypi/")


def _property_name(prop: dict[str, Any]) -> str:
    """DT stores `cdx:npm:package:development` as groupName `cdx` + propertyName
    `npm:package:development`; CycloneDX JSON uses a single `name`."""
    if "propertyName" in prop:
        group = prop.get("groupName")
        return f"{group}:{prop['propertyName']}" if group else str(prop["propertyName"])
    return str(prop.get("name", ""))


def _infer_scope(component: dict[str, Any], properties: list[dict[str, Any]]) -> str:
    """FR-4.2: production/development classification from the CycloneDX `scope` field and
    generator properties."""
    if str(component.get("scope", "")).lower() in _DEV_SCOPE_MARKERS:
        return "development"
    for prop in properties:
        name = _property_name(prop).lower()
        value = str(prop.get("propertyValue", prop.get("value", ""))).lower()
        if name in _DEV_PROPERTY_NAMES and value == "true":
            return "development"
    return "production"


def _extract_kev_flag(vulnerability: dict[str, Any]) -> bool:
    """FR-4.1: CISA KEV listing must force Critical regardless of CVSS. Dependency-Track
    has not settled on one field name across versions, so this checks the plausible
    candidates and falls back to scanning aliases/references for a KEV mention."""
    for key in ("cisaKevInTheWild", "cisaKevDateAdded", "kev"):
        value = vulnerability.get(key)
        if isinstance(value, bool) and value:
            return True
        if isinstance(value, str) and value:
            return True
    for alias in vulnerability.get("aliases") or []:
        if "kev" in str(alias).lower():
            return True
    return False


def _extract_epss(vulnerability: dict[str, Any]) -> float | None:
    value = vulnerability.get("epssScore")
    return float(value) if value is not None else None


def _extract_cvss(vulnerability: dict[str, Any]) -> float | None:
    """Prefer CVSSv3 (matches Requirement.md Section 12's 0-10 CVSS bands): the reported
    score, else one computed from the v3 vector, and CVSSv2 only as a last resort."""
    if vulnerability.get("cvssV3BaseScore") is not None:
        return float(vulnerability["cvssV3BaseScore"])
    computed = base_score_from_vector(vulnerability.get("cvssV3Vector"))
    if computed is not None:
        return computed
    if vulnerability.get("cvssV2BaseScore") is not None:
        return float(vulnerability["cvssV2BaseScore"])
    return None


def _resolve_cve_id(vulnerability: dict[str, Any]) -> str | None:
    """The platform keys findings by CVE where one exists (search, KEV/EPSS lookups);
    a GHSA/OSV-only advisory keeps its own ID."""
    vuln_id = vulnerability.get("vulnId")
    if vuln_id and str(vuln_id).upper().startswith("CVE-"):
        return str(vuln_id)
    for alias in vulnerability.get("aliases") or []:
        cve = alias.get("cveId") if isinstance(alias, dict) else None
        if cve:
            return str(cve)
    return str(vuln_id) if vuln_id else None


# DT project tags the pipeline sets on upload (docs/workflows.md W1), e.g. "commit:9f2c1ab".
# DT lower-cases tags and does not allow ":" inside a value, so digests arrive as
# "digest:sha256-<hex>" and are turned back into "sha256:<hex>".
_EVIDENCE_TAGS = ("commit", "digest", "tool", "pipeline")


def _evidence_from_tags(tags: list[dict[str, Any]] | None) -> dict[str, str]:
    evidence: dict[str, str] = {}
    for tag in tags or []:
        name, _, value = str(tag.get("name", "")).partition(":")
        if name in _EVIDENCE_TAGS and value and name not in evidence:
            evidence[name] = value.replace("-", ":", 1) if name == "digest" else value
    return evidence


def _epoch_ms(value: Any) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value) / 1000, tz=UTC)
    except (TypeError, ValueError):
        return None


class DependencyTrackConnector:
    """`SCAConnector` implementation for OWASP Dependency-Track."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        upload_api_key: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        settings = get_settings()
        self._base_url = (base_url or settings.dependency_track_base_url).rstrip("/")
        self._api_key = api_key or settings.dependency_track_api_key
        self._upload_api_key = upload_api_key or settings.dependency_track_upload_api_key
        self._transport = transport

    def _client(self, api_key: str | None = None) -> httpx.Client:
        return httpx.Client(
            base_url=self._base_url,
            headers={"X-Api-Key": api_key or self._api_key, "Accept": "application/json"},
            timeout=30.0,
            transport=self._transport,
        )

    def list_projects(self) -> list[SCAProject]:
        with self._client() as client:
            projects: list[SCAProject] = []
            page = 1
            while True:
                response = client.get(
                    "/api/v1/project", params={"pageNumber": page, "pageSize": 100}
                )
                response.raise_for_status()
                batch = response.json()
                if not batch:
                    break
                for item in batch:
                    projects.append(
                        SCAProject(
                            external_id=item["uuid"],
                            name=item["name"],
                            version=item.get("version") or "unspecified",
                            evidence=_evidence_from_tags(item.get("tags")),
                            last_bom_import=_epoch_ms(item.get("lastBomImport")),
                        )
                    )
                if len(batch) < 100:
                    break
                page += 1
            return projects

    def get_components(self, project_external_id: str) -> list[SCAComponent]:
        with self._client() as client:
            response = client.get(f"/api/v1/component/project/{project_external_id}")
            response.raise_for_status()
            components: list[SCAComponent] = []
            for item in response.json():
                properties: list[dict[str, Any]] = item.get("properties") or []
                if not properties and str(item.get("purl") or "").startswith(_PROPERTY_ECOSYSTEMS):
                    prop_response = client.get(f"/api/v1/component/{item['uuid']}/property")
                    prop_response.raise_for_status()
                    properties = prop_response.json()
                components.append(
                    SCAComponent(
                        name=item["name"],
                        version=item.get("version"),
                        license=(item.get("resolvedLicense") or {}).get("licenseId")
                        or item.get("license"),
                        purl=item.get("purl"),
                        scope=_infer_scope(item, properties),
                    )
                )
            return components

    def get_findings(self, project_external_id: str) -> list[SCAFinding]:
        with self._client() as client:
            response = client.get(f"/api/v1/finding/project/{project_external_id}")
            response.raise_for_status()
            findings: list[SCAFinding] = []
            for item in response.json():
                # FR-8: a Finding already suppressed via VEX on the SCA platform side
                # should not be re-raised as a new open Finding on our side.
                if (item.get("analysis") or {}).get("isSuppressed"):
                    continue
                component = item.get("component") or {}
                vulnerability = item.get("vulnerability") or {}
                cve_id = _resolve_cve_id(vulnerability)
                if not cve_id:
                    continue
                findings.append(
                    SCAFinding(
                        component_purl=component.get("purl"),
                        component_name=component.get("name", "unknown"),
                        component_version=component.get("version"),
                        cve_id=cve_id,
                        cvss=_extract_cvss(vulnerability),
                        epss=_extract_epss(vulnerability),
                        kev_flag=_extract_kev_flag(vulnerability),
                    )
                )
            return merge_findings(findings)

    def export_bom(self, project_external_id: str) -> bytes:
        with self._client() as client:
            response = client.get(
                f"/api/v1/bom/cyclonedx/project/{project_external_id}",
                params={"format": "json", "variant": "inventory"},
                headers={"Accept": "application/vnd.cyclonedx+json"},
            )
            response.raise_for_status()
            return response.content

    def upload_bom(self, project_name: str, project_version: str, bom_bytes: bytes) -> None:
        """FR-2.6: forwards a manually-collected SBOM into Dependency-Track's normal
        ingestion pipeline (auto-creating the project there if needed), the same
        endpoint an automated CI/CD push would use."""
        payload = {
            "projectName": project_name,
            "projectVersion": project_version,
            "autoCreate": True,
            "bom": base64.b64encode(bom_bytes).decode("ascii"),
        }
        with self._client(self._upload_api_key) as client:
            response = client.put("/api/v1/bom", json=payload)
            response.raise_for_status()
