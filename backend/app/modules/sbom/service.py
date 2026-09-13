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

import logging
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.config import get_settings
from app.integrations.dependency_track import DependencyTrackConnector
from app.integrations.sca_connector import SCAComponent, SCAConnector, SCAFinding
from app.models.component import Component
from app.models.finding import Finding, FindingSource, FindingStatus
from app.models.inventory import Application, AppVersion
from app.models.scan_result import ScanResult
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
) -> tuple[int, int]:
    """FR-3.2/3.3: reconciles the SCA platform's current finding set against ours —
    creates new Findings, updates changed CVSS/EPSS/KEV on existing ones (re-tiering
    through the Policy engine), and auto-closes SBOM Findings that no longer appear
    (fixed, without waiting for a rebuild/redeploy — the point of FR-3.2)."""
    detected_on = datetime.now(UTC).date()
    policy = policy_service.get_effective_policy(db, detected_on)

    existing_open = {
        (f.component_id, f.cve_id): f
        for f in db.execute(
            select(Finding).where(
                Finding.app_version_id == version.id,
                Finding.source == FindingSource.SBOM,
                Finding.status == FindingStatus.OPEN,
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
        existing = existing_open.get(key)
        if existing is not None:
            existing.cvss = sca_finding.cvss
            existing.epss = sca_finding.epss
            existing.kev_flag = sca_finding.kev_flag
            existing.severity_tier = decision.tier
            existing.policy_version = policy.version
            existing.due_date = policy_service.compute_due_date(policy, decision.tier, detected_on)
            continue

        # Re-matches a Finding that had been marked Fixed (e.g. reintroduced by a
        # downgrade): reopen it rather than create a duplicate row, since the unique
        # constraint on (app_version_id, component_id, cve_id) forbids two rows anyway.
        reopened = db.execute(
            select(Finding).where(
                Finding.app_version_id == version.id,
                Finding.component_id == component.id,
                Finding.cve_id == sca_finding.cve_id,
            )
        ).scalar_one_or_none()
        if reopened is not None:
            reopened.status = FindingStatus.OPEN
            reopened.fixed_at = None
            reopened.cvss = sca_finding.cvss
            reopened.epss = sca_finding.epss
            reopened.kev_flag = sca_finding.kev_flag
            reopened.severity_tier = decision.tier
            reopened.policy_version = policy.version
            reopened.due_date = policy_service.compute_due_date(policy, decision.tier, detected_on)
            continue

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
            due_date=policy_service.compute_due_date(policy, decision.tier, detected_on),
            first_detected_at=datetime.now(UTC),
        )
        db.add(new_finding)
        created += 1
        db.flush()  # assigns new_finding.id before routing can reference it
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
    for existing_key, finding in existing_open.items():
        if existing_key not in seen:
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
    return created, closed


def sync_from_connector(
    db: Session, connector: SCAConnector | None = None, actor: str = SYSTEM_ACTOR
) -> DependencyTrackSyncResult:
    """FR-2.5/FR-3: pull-sync every project the SCA platform knows about into our own
    Application/AppVersion/Component/Finding tables."""
    connector = connector or DependencyTrackConnector()

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
            sca_findings = connector.get_findings(project.external_id)

            application, created = get_or_create_application_by_name(
                db, project.name, owner_team=UNASSIGNED_OWNER_TEAM
            )
            if created:
                result.applications_auto_created += 1

            version = _get_or_create_app_version(db, application, project.version)

            by_key = _upsert_components(db, version, components)
            result.components_upserted += len(components)

            created_count, closed_count = _upsert_findings(db, version, by_key, sca_findings)
            result.findings_created += created_count
            result.findings_auto_closed += closed_count

            version.last_ingested_at = datetime.now(UTC)
            version.is_stale = False
            db.add(
                ScanResult(
                    app_version_id=version.id,
                    scan_type="sbom",
                    scanned_at=datetime.now(UTC),
                    result_status="completed",
                    is_manual_upload=False,
                )
            )
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
    db.add(
        ScanResult(
            app_version_id=version.id,
            scan_type="sbom",
            scanned_at=datetime.now(UTC),
            result_status="completed",
            is_manual_upload=True,
            uploaded_by=actor,
        )
    )

    forwarded = False
    forward_error: str | None = None
    settings = get_settings()
    if settings.dependency_track_api_key:
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
