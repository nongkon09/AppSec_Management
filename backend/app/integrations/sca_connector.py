"""Pluggable SCA/SBOM platform connector interface (Requirement.md FR-2.5).

FR-2.5 requires an Integration Layer that starts with OWASP Dependency-Track but can
extend to other Enterprise SCA platforms (Snyk/Mend/Sonatype) "โดยไม่แก้ Core" — without
touching the sync logic in `app.modules.sbom.service`. That service is written against
this Protocol only; adding a new SCA platform means writing one new connector class, not
modifying the sync/upsert code.
"""

from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Protocol


@dataclass(frozen=True)
class SCAProject:
    """One project/application as the SCA platform sees it."""

    external_id: str
    name: str
    version: str
    # Pipeline-supplied evidence (docs/risk-exception-design.md 3.7): commit, digest, tool,
    # pipeline run. Empty when the pipeline did not send them.
    evidence: dict[str, str] = field(default_factory=dict)
    # When the SCA platform last received an SBOM for this version; None if unknown.
    last_bom_import: datetime | None = None


@dataclass(frozen=True)
class SCAComponent:
    """One SBOM component, normalized across SCA platforms."""

    name: str
    version: str | None
    license: str | None
    purl: str | None
    # "production" / "development" (FR-4.2 dependency scope).
    scope: str


@dataclass(frozen=True)
class SCAFinding:
    """One vulnerability match the SCA platform has already made against a component.

    Dependency-Track (and equivalents) own vulnerability intelligence and matching
    (FR-3.1/3.2 — sync against NVD/OSV/GHSA/KEV/EPSS is the SCA platform's job, per
    Requirement.md Section 14 assumptions); this platform only pulls the result.
    """

    component_purl: str | None
    component_name: str
    component_version: str | None
    cve_id: str
    cvss: float | None
    epss: float | None
    kev_flag: bool


def merge_findings(findings: Iterable[SCAFinding]) -> list[SCAFinding]:
    """Collapses findings for the same component and vulnerability ID (several advisories
    often describe one CVE), keeping the highest CVSS/EPSS and any KEV flag."""

    def higher(a: float | None, b: float | None) -> float | None:
        return b if a is None else a if b is None else max(a, b)

    merged: dict[tuple[str, str], SCAFinding] = {}
    for finding in findings:
        key = (finding.component_name, finding.cve_id.upper())
        current = merged.get(key)
        merged[key] = (
            finding
            if current is None
            else replace(
                current,
                cvss=higher(current.cvss, finding.cvss),
                epss=higher(current.epss, finding.epss),
                kev_flag=current.kev_flag or finding.kev_flag,
            )
        )
    return list(merged.values())


class SCAConnector(Protocol):
    """Read-only integration surface FR-2.5 requires (FR-2.7.4: separate read-only
    Service Account key from the one CI/CD pipelines use to push SBOM), plus the single
    write operation (`upload_bom`) needed for the manual/COTS intake path (FR-2.6.1)."""

    def list_projects(self) -> list[SCAProject]:
        """All projects/versions currently known to the SCA platform."""
        ...

    def get_components(self, project_external_id: str) -> list[SCAComponent]:
        """SBOM components for one project (FR-3.2 delta-matching input)."""
        ...

    def get_findings(self, project_external_id: str) -> list[SCAFinding]:
        """Vulnerabilities the SCA platform has already matched for one project."""
        ...

    def export_bom(self, project_external_id: str) -> bytes:
        """The SBOM the platform currently holds for this project (scan evidence)."""
        ...

    def upload_bom(self, project_name: str, project_version: str, bom_bytes: bytes) -> None:
        """Forward a manually-collected SBOM (FR-2.6.1/FR-2.6.2) so it enters the SCA
        platform's normal analysis pipeline — the same one an automated CI/CD push
        uses — rather than a parallel, unanalyzed path."""
        ...
