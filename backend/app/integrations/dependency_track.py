"""OWASP Dependency-Track connector (Requirement.md FR-2.5, FR-2.7.4, FR-3.1).

Implements `SCAConnector` against Dependency-Track's v1 REST API. Authenticates with a
`X-Api-Key` header per FR-2.7 — the key configured here (`settings.dependency_track_api_key`)
must be a **read-only** Service Account key, separate from the per-team/per-project keys
CI/CD pipelines use to push SBOM directly to Dependency-Track (FR-2.7.4); this platform
never receives that push (FR-2.7 confirmed).

Field-mapping note: `component.scope` (production/development, FR-4.2) and the CISA KEV
flag are not part of Dependency-Track's stable core schema and vary by generator/DT
version. The heuristics below (`_infer_scope`, `_extract_kev_flag`) are a best-effort
mapping — verify field names against the deployed Dependency-Track version during
integration testing and adjust there; nothing else in the sync pipeline depends on the
exact source field.
"""

import base64
import logging
from typing import Any

import httpx

from app.core.config import get_settings
from app.integrations.sca_connector import SCAComponent, SCAFinding, SCAProject

logger = logging.getLogger(__name__)

# CycloneDX/generator scope hints that indicate a dependency is development-only.
_DEV_SCOPE_MARKERS = {"optional", "excluded"}
_DEV_PROPERTY_NAMES = {
    "cdx:npm:package:development",
    "cdx:pip:package:development",
}


def _infer_scope(component: dict[str, Any]) -> str:
    """FR-4.2: best-effort production/development classification from CycloneDX-derived
    fields Dependency-Track exposes on a component."""
    if str(component.get("scope", "")).lower() in _DEV_SCOPE_MARKERS:
        return "development"
    for prop in component.get("properties") or []:
        name = str(prop.get("name", "")).lower()
        value = str(prop.get("value", "")).lower()
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
    """Prefer CVSSv3 (matches Requirement.md Section 12's 0-10 CVSS bands); fall back to
    CVSSv2 only if a vulnerability has no v3 score at all."""
    for key in ("cvssV3BaseScore", "cvssV2BaseScore"):
        value = vulnerability.get(key)
        if value is not None:
            return float(value)
    return None


class DependencyTrackConnector:
    """`SCAConnector` implementation for OWASP Dependency-Track."""

    def __init__(self, base_url: str | None = None, api_key: str | None = None) -> None:
        settings = get_settings()
        self._base_url = (base_url or settings.dependency_track_base_url).rstrip("/")
        self._api_key = api_key or settings.dependency_track_api_key

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self._base_url,
            headers={"X-Api-Key": self._api_key, "Accept": "application/json"},
            timeout=30.0,
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
            return [
                SCAComponent(
                    name=item["name"],
                    version=item.get("version"),
                    license=(item.get("resolvedLicense") or {}).get("licenseId")
                    or item.get("license"),
                    purl=item.get("purl"),
                    scope=_infer_scope(item),
                )
                for item in response.json()
            ]

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
                cve_id = vulnerability.get("vulnId")
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
            return findings

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
        with self._client() as client:
            response = client.put("/api/v1/bom", json=payload)
            response.raise_for_status()
