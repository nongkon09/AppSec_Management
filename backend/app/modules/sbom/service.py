"""SBOM ingestion: Dependency-Track pull-sync, manual/COTS upload, staleness sweep
(Requirement.md FR-2, FR-3).

Per FR-2.7, automated CI/CD pushes SBOM directly to Dependency-Track — this platform
never receives that push. What this module does instead:

- `sync_from_connector`: pulls Components + already-matched Findings from the SCA
  platform (FR-2.5, FR-2.7.4, FR-3.1/3.2/3.3) and reconciles them into our own tables,
  running every Finding through the Policy engine (FR-4/FR-5) exactly as manually
  created Findings are.
- `ingest_manual_sbom`: the COTS/Vendor manual-upload path (FR-2.6) that *is* ours to
  build, since Dependency-Track has no notion of "a vendor handed us a file."
- `check_stale_versions`: FR-2.4 staleness sweep.
"""

import hashlib
import logging
import uuid
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.config import get_settings
from app.integrations.dependency_track import DependencyTrackConnector
from app.integrations.sca_connector import (
    SCAComponent,
    SCAConnector,
    SCAFinding,
    SCAProject,
    merge_findings,
)
from app.integrations.threat_intel import PublicFeedThreatIntel, ThreatIntel
from app.models.component import Component
from app.models.finding import Finding, FindingSource, FindingStatus, build_issue_key
from app.models.inventory import Application, AppVersion
from app.models.scan_result import ScanFinding, ScanResult
from app.modules.deployments.service import refresh_active_versions
from app.modules.exceptions import coverage as exception_coverage
from app.modules.findings import sla
from app.modules.integrations import service as integrations_service
from app.modules.inventory.service import get_or_create_application_by_name
from app.modules.policy import service as policy_service
from app.modules.sbom.parser import ParsedComponent, parse_sbom
from app.schemas.sbom import (
    DependencyTrackSyncResult,
    ManualSbomUploadResult,
    StaleCheckResult,
)

logger = logging.getLogger(__name__)

SYSTEM_ACTOR = "system"
# Placeholder owner_team for Applications auto-created from an unregistered SCA project
# (FR-1.5); AppSec confirms the real owner via ownership_confirmed=False on the record.
UNASSIGNED_OWNER_TEAM = "Unassigned"


def _get_or_create_app_version(
    db: Session, application: Application, version_label: str
) -> AppVersion:
    version = db.execute(
        select(AppVersion).where(
            AppVersion.application_id == application.id,
            AppVersion.version_label == version_label,
        )
    ).scalar_one_or_none()
    if version is not None:
        return version
    version = AppVersion(application_id=application.id, version_label=version_label)
    db.add(version)
    db.flush()
    return version


def _component_key(name: str) -> str:
    """Identity within one AppVersion is the component name alone. purl is *not* usable
    as an identity key here: it embeds the version (`pkg:maven/.../log4j-core@2.14.1`),
    so a re-scan that reports the same package at a new version would produce a purl
    that has never been seen before and would never match the existing row — every
    version bump would look like a brand-new component instead of an update to it."""
    return name


def _upsert_components(
    db: Session,
    version: AppVersion,
    components: Sequence[SCAComponent] | Sequence[ParsedComponent],
) -> dict[str, Component]:
    """Inserts new Components and updates existing ones for this AppVersion, matched by
    name (version/license/purl/scope are treated as mutable attributes of that named
    component, not part of its identity). Returns a lookup so callers can resolve a
    Finding's component without a second query per row."""
    existing = list(
        db.execute(select(Component).where(Component.app_version_id == version.id)).scalars()
    )
    by_key: dict[str, Component] = {
        _component_key(component.component_name): component for component in existing
    }

    for source in components:
        key = _component_key(source.name)
        row = by_key.get(key)
        if row is None:
            row = Component(app_version_id=version.id, component_name=source.name)
            db.add(row)
            by_key[key] = row
        row.version = source.version
        row.license = source.license
        row.purl = source.purl
        row.scope = source.scope
    db.flush()
    return by_key


def _resolve_component(by_key: dict[str, Component], finding: SCAFinding) -> Component | None:
    return by_key.get(_component_key(finding.component_name))


def _upsert_findings(
    db: Session,
    version: AppVersion,
    by_key: dict[str, Component],
    sca_findings: Sequence[SCAFinding],
) -> tuple[int, int, list[Finding]]:
    """FR-3.2/3.3: reconciles the SCA platform's current finding set for one version.

    - Existing rows keep their status: a risk-accepted or suppressed decision must survive
      every sync, not just open ones.
    - Due dates come from `sla_started_on` (docs/risk-exception-design.md 3.2), never from
      the sync date, so repeated syncs cannot push a deadline forward.
    - A new row inherits the SLA anchor of the same issue in other versions of the
      Application, and any approved exception covering that issue.
    - Rows no longer reported are marked FIXED (FR-3.2), whatever their status was.
    """
    today = datetime.now(UTC).date()
    policy = policy_service.get_effective_policy(db, today)
    application_id = version.application_id

    current = {
        (f.component_id, f.cve_id): f
        for f in db.execute(
            select(Finding).where(
                Finding.app_version_id == version.id, Finding.source == FindingSource.SBOM
            )
        ).scalars()
    }

    created = 0
    # Finding.component_id/cve_id are nullable on the model (SAST/Pentest findings have
    # neither), but every SBOM Finding this function touches always has both set.
    seen: set[tuple[uuid.UUID | None, str | None]] = set()
    for sca_finding in sca_findings:
        component = _resolve_component(by_key, sca_finding)
        if component is None:
            continue  # SCA platform matched a component we could not resolve; skip it.

        key = (component.id, sca_finding.cve_id)
        seen.add(key)
        decision = policy_service.evaluate_severity(
            policy,
            cvss=sca_finding.cvss,
            epss=sca_finding.epss,
            kev_flag=sca_finding.kev_flag,
            scope=component.scope,
        )

        finding = current.get(key)
        if finding is not None:
            finding.cvss = sca_finding.cvss
            finding.epss = sca_finding.epss
            finding.kev_flag = sca_finding.kev_flag
            finding.severity_tier = decision.tier
            finding.policy_version = policy.version
            if finding.status == FindingStatus.FIXED:
                # Reintroduced after a real fix: a new exposure, so a new SLA anchor
                # unless the issue is still unresolved elsewhere in the Application.
                finding.status = FindingStatus.OPEN
                finding.fixed_at = None
                finding.residual_severity_tier = None
                finding.sla_started_on = sla.resolve_sla_start(
                    db,
                    application_id,
                    finding.issue_key,
                    today=today,
                    exclude_finding_id=finding.id,
                )
                record_audit(
                    db,
                    actor=SYSTEM_ACTOR,
                    action="finding.reintroduced",
                    entity_type="finding",
                    entity_id=finding.id,
                    after={"sla_started_on": finding.sla_started_on.isoformat()},
                )
                exception_coverage.apply_to_finding(db, finding)
            sla.refresh_due_date(policy, finding)
            continue

        issue_key = build_issue_key(
            FindingSource.SBOM,
            component_name=component.component_name,
            purl=component.purl,
            cve_id=sca_finding.cve_id,
            title=None,
        )
        new_finding = Finding(
            app_version_id=version.id,
            component_id=component.id,
            source=FindingSource.SBOM,
            cve_id=sca_finding.cve_id,
            cvss=sca_finding.cvss,
            epss=sca_finding.epss,
            kev_flag=sca_finding.kev_flag,
            severity_tier=decision.tier,
            status=FindingStatus.OPEN,
            policy_version=policy.version,
            issue_key=issue_key,
            sla_started_on=sla.resolve_sla_start(db, application_id, issue_key, today=today),
            first_detected_at=datetime.now(UTC),
        )
        sla.refresh_due_date(policy, new_finding)
        db.add(new_finding)
        created += 1
        db.flush()  # assigns new_finding.id before routing can reference it
        current[key] = new_finding
        exception_coverage.apply_to_finding(db, new_finding)
        if new_finding.status != FindingStatus.OPEN:
            continue  # already covered by an approved exception; nothing to ticket
        try:
            # FR-7.2: route a brand-new Finding to whatever connector is configured
            # for its Severity Tier. Best-effort, same reasoning as the auto-close call
            # below — an ITSM outage must not roll back an otherwise-good SBOM sync.
            integrations_service.route_finding_to_connectors(db, new_finding)
        except Exception:  # noqa: BLE001 - ticket routing is best-effort
            logger.exception(
                "FR-7.2 routing failed for finding %s; SBOM sync continues", new_finding.id
            )

    closed = 0
    for existing_key, finding in current.items():
        if existing_key in seen or finding.status == FindingStatus.FIXED:
            continue
        finding.status = FindingStatus.FIXED
        finding.fixed_at = datetime.now(UTC)
        closed += 1
        db.flush()  # the FIXED status must be visible before the ticket close call
        try:
            # FR-7.5: auto-close whatever ticket(s) this Finding raised, in every
            # system it was raised in. A connector outage here must not roll back
            # the SBOM progress already made this sync — isolated per Finding.
            integrations_service.on_finding_fixed(db, finding)
        except Exception:  # noqa: BLE001 - ticket auto-close is best-effort
            logger.exception(
                "FR-7.5 auto-close failed for finding %s; SBOM sync continues", finding.id
            )

    db.flush()
    present = [current[key] for key in seen if key in current]
    return created, closed, present


def _store_sbom(version_id: uuid.UUID, content: bytes) -> tuple[str, str]:
    """Content-addressed evidence file: the same SBOM is stored once however often it is
    snapshotted, and its hash proves which document a scan was based on."""
    digest = hashlib.sha256(content).hexdigest()
    directory = Path(get_settings().sbom_evidence_dir) / str(version_id)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{digest}.json"
    if not path.exists():
        path.write_bytes(content)
    return digest, str(path)


def _latest_snapshot(db: Session, version_id: uuid.UUID) -> ScanResult | None:
    return (
        db.execute(
            select(ScanResult)
            .where(ScanResult.app_version_id == version_id, ScanResult.scan_type == "sbom")
            .order_by(ScanResult.scanned_at.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )


def _is_new_scan(db: Session, version: AppVersion, project: SCAProject) -> bool:
    """A snapshot is only worth recording when the SCA platform has a newer SBOM than the
    last one we captured; otherwise every 6-hourly sync would add a history row."""
    if project.last_bom_import is None:
        return True
    latest = _latest_snapshot(db, version.id)
    if latest is None or latest.sca_bom_imported_at is None:
        return True
    previous = latest.sca_bom_imported_at
    if previous.tzinfo is None:
        previous = previous.replace(tzinfo=UTC)
    return project.last_bom_import > previous


def _record_snapshot(
    db: Session,
    version: AppVersion,
    connector: SCAConnector,
    project: SCAProject,
    present: list[Finding],
) -> None:
    sha = path = None
    status = "completed"
    try:
        sha, path = _store_sbom(version.id, connector.export_bom(project.external_id))
    except Exception:  # noqa: BLE001 - evidence capture must not fail the sync
        logger.exception("Could not export the SBOM for %s %s", project.name, project.version)
        status = "completed_without_sbom"
    snapshot = ScanResult(
        app_version_id=version.id,
        scan_type="sbom",
        # When the SBOM reached the SCA platform, not when we happened to sync it.
        scanned_at=project.last_bom_import or datetime.now(UTC),
        result_status=status,
        is_manual_upload=False,
        source_tool=project.evidence.get("tool"),
        image_digest=project.evidence.get("digest"),
        commit_sha=project.evidence.get("commit"),
        pipeline_run=project.evidence.get("pipeline"),
        sca_bom_imported_at=project.last_bom_import,
        sbom_sha256=sha,
        sbom_path=path,
    )
    db.add(snapshot)
    db.flush()
    for finding in present:
        db.add(
            ScanFinding(
                scan_result_id=snapshot.id,
                finding_id=finding.id,
                severity_tier=finding.effective_severity_tier.value,
                status=finding.status.value,
            )
        )


def _enrich(findings: list[SCAFinding], intel: ThreatIntel) -> list[SCAFinding]:
    """FR-4.1: identify each advisory by its CVE and add exploitation signals.

    An advisory that maps to exactly one CVE is re-keyed to it, so duplicate advisories
    for that CVE merge. One that lists several CVEs (e.g. a 2026 advisory that also cites
    the 2021 CVE it regresses) keeps its own ID — picking one CVE would mislabel it — but
    KEV and EPSS are still taken from all of them: KEV if any is listed, the highest EPSS.
    Values the SCA platform already supplied are kept; KEV is never cleared.
    """
    aliases = intel.cve_aliases(f.cve_id for f in findings)
    if aliases:
        findings = merge_findings(
            replace(f, cve_id=cves[0]) if len(cves := aliases.get(f.cve_id, ())) == 1 else f
            for f in findings
        )

    def related_cves(finding: SCAFinding) -> tuple[str, ...]:
        if finding.cve_id.upper().startswith("CVE-"):
            return (finding.cve_id.upper(),)
        return aliases.get(finding.cve_id, ())

    missing_epss = [cve for f in findings if f.epss is None for cve in related_cves(f)]
    epss = intel.epss_scores(missing_epss) if missing_epss else {}

    def best_epss(finding: SCAFinding) -> float | None:
        if finding.epss is not None:
            return finding.epss
        scores = [epss[cve] for cve in related_cves(finding) if cve in epss]
        return max(scores) if scores else None

    return [
        replace(
            finding,
            kev_flag=finding.kev_flag or any(intel.is_kev(cve) for cve in related_cves(finding)),
            epss=best_epss(finding),
        )
        for finding in findings
    ]


def sync_from_connector(
    db: Session,
    connector: SCAConnector | None = None,
    actor: str = SYSTEM_ACTOR,
    threat_intel: ThreatIntel | None = None,
) -> DependencyTrackSyncResult:
    """FR-2.5/FR-3: pull-sync every project the SCA platform knows about into our own
    Application/AppVersion/Component/Finding tables."""
    connector = connector or DependencyTrackConnector()
    threat_intel = threat_intel or PublicFeedThreatIntel()

    result = DependencyTrackSyncResult(
        projects_seen=0,
        applications_auto_created=0,
        components_upserted=0,
        findings_created=0,
        findings_auto_closed=0,
    )

    projects = connector.list_projects()
    for project in projects:
        result.projects_seen += 1
        try:
            # Pull everything from the connector *before* writing anything to our own
            # database. get_or_create_application_by_name commits immediately, so if a
            # later connector call for this project failed, a rollback could not have
            # undone that already-committed Application row — fetching first means a
            # failed project never touches the database at all.
            components = connector.get_components(project.external_id)
            sca_findings = _enrich(connector.get_findings(project.external_id), threat_intel)

            application, created = get_or_create_application_by_name(
                db, project.name, owner_team=UNASSIGNED_OWNER_TEAM
            )
            if created:
                result.applications_auto_created += 1

            version = _get_or_create_app_version(db, application, project.version)
            new_scan = _is_new_scan(db, version, project)

            by_key = _upsert_components(db, version, components)
            result.components_upserted += len(components)

            created_count, closed_count, present = _upsert_findings(
                db, version, by_key, sca_findings
            )
            result.findings_created += created_count
            result.findings_auto_closed += closed_count

            version.last_ingested_at = project.last_bom_import or datetime.now(UTC)
            version.is_stale = False
            if project.evidence.get("commit") and not version.commit_sha:
                version.commit_sha = project.evidence["commit"][:64]
            refresh_active_versions(db, application.id)
            if new_scan:
                _record_snapshot(db, version, connector, project, present)
            db.commit()
        except Exception as exc:  # noqa: BLE001 - one bad project must not abort the sync
            db.rollback()
            result.errors.append(f"{project.name} {project.version}: {exc}")

    record_audit(
        db,
        actor=actor,
        action="sbom.dependency_track_sync",
        entity_type="sbom_sync",
        entity_id=str(uuid.uuid4()),
        after=result.model_dump(mode="json"),
    )
    db.commit()
    return result


def ingest_manual_sbom(
    db: Session,
    *,
    application: Application,
    version_label: str,
    raw_bytes: bytes,
    actor: str,
    connector: SCAConnector | None = None,
    source_tool: str | None = None,
    image_digest: str | None = None,
    commit_sha: str | None = None,
) -> ManualSbomUploadResult:
    """FR-2.6.1/2.6.2: COTS/Vendor manual SBOM upload. Validates the format, ingests
    Components directly (so the upload is useful even before the SCA platform has
    analyzed it), and best-effort forwards the raw file into the SCA platform's normal
    pipeline so it gets vulnerability-matched on the next pull-sync — "เข้าสู่
    Application/Version เดียวกับ Automated Flow"."""
    parsed = parse_sbom(raw_bytes)  # raises SbomFormatError on invalid input

    version = _get_or_create_app_version(db, application, version_label)
    _upsert_components(db, version, parsed.components)

    version.last_ingested_at = datetime.now(UTC)
    version.is_stale = False
    if commit_sha and not version.commit_sha:
        version.commit_sha = commit_sha[:64]
    refresh_active_versions(db, application.id)
    # The uploaded file itself is the evidence: store it and its hash exactly as received.
    sha, path = _store_sbom(version.id, raw_bytes)
    db.add(
        ScanResult(
            app_version_id=version.id,
            scan_type="sbom",
            scanned_at=datetime.now(UTC),
            result_status="completed",
            is_manual_upload=True,
            uploaded_by=actor,
            source_tool=source_tool,
            image_digest=image_digest,
            commit_sha=commit_sha,
            sbom_sha256=sha,
            sbom_path=path,
        )
    )

    forwarded = False
    forward_error: str | None = None
    settings = get_settings()
    if settings.dependency_track_upload_api_key:
        try:
            (connector or DependencyTrackConnector()).upload_bom(
                application.app_name, version_label, raw_bytes
            )
            forwarded = True
        except Exception as exc:  # noqa: BLE001 - a DT outage must not block the upload
            forward_error = str(exc)

    record_audit(
        db,
        actor=actor,
        action="sbom.manual_upload",
        entity_type="app_version",
        entity_id=version.id,
        after={
            "sbom_format": parsed.sbom_format,
            "components_ingested": len(parsed.components),
            "forwarded_to_sca_platform": forwarded,
        },
    )
    db.commit()

    return ManualSbomUploadResult(
        app_version_id=version.id,
        sbom_format=parsed.sbom_format,
        components_ingested=len(parsed.components),
        forwarded_to_sca_platform=forwarded,
        forward_error=forward_error,
    )


def check_stale_versions(db: Session, threshold_days: int | None = None) -> StaleCheckResult:
    """FR-2.4: flags an AppVersion "Stale/ไม่ Sync" once it has gone longer than
    `threshold_days` without a new SBOM — measured from the last ingest, or from the
    version's creation if it has never been ingested at all."""
    settings = get_settings()
    days = threshold_days if threshold_days is not None else settings.stale_sbom_days
    cutoff = datetime.now(UTC) - timedelta(days=days)

    candidates = (
        db.execute(
            select(AppVersion).where(
                AppVersion.is_stale.is_(False),
                (
                    (AppVersion.last_ingested_at.is_(None) & (AppVersion.created_at < cutoff))
                    | (
                        AppVersion.last_ingested_at.is_not(None)
                        & (AppVersion.last_ingested_at < cutoff)
                    )
                ),
            )
        )
        .scalars()
        .all()
    )

    newly_flagged: list[uuid.UUID] = []
    for version in candidates:
        version.is_stale = True
        newly_flagged.append(version.id)

    if newly_flagged:
        record_audit(
            db,
            actor=SYSTEM_ACTOR,
            action="sbom.stale_check",
            entity_type="sbom_sync",
            entity_id=str(uuid.uuid4()),
            after={"newly_flagged_count": len(newly_flagged), "threshold_days": days},
        )
    db.commit()

    total_stale = (
        db.execute(select(AppVersion).where(AppVersion.is_stale.is_(True))).scalars().all()
    )

    return StaleCheckResult(
        newly_flagged_version_ids=newly_flagged, total_stale_versions=len(total_stale)
    )
