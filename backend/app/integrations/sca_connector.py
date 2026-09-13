"""Pluggable SCA/SBOM platform connector interface (Requirement.md FR-2.5).

FR-2.5 requires an Integration Layer that starts with OWASP Dependency-Track but can
extend to other Enterprise SCA platforms (Snyk/Mend/Sonatype) "โดยไม่แก้ Core" — without
touching the sync logic in `app.modules.sbom.service`. That service is written against
this Protocol only; adding a new SCA platform means writing one new connector class, not
modifying the sync/upsert code.
"""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class SCAProject:
    """One project/application as the SCA platform sees it."""

    external_id: str
    name: str
    version: str


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

    def upload_bom(self, project_name: str, project_version: str, bom_bytes: bytes) -> None:
        """Forward a manually-collected SBOM (FR-2.6.1/FR-2.6.2) so it enters the SCA
        platform's normal analysis pipeline — the same one an automated CI/CD push
        uses — rather than a parallel, unanalyzed path."""
        ...
