"""Background jobs (Requirement.md FR-3.1 pull-sync cadence, FR-2.4 staleness sweep).

Guarded by `settings.enable_scheduler` (default off) so importing `app.main` — as every
test does — never starts a background job or opens an unwanted connection to the SCA
platform. Real deployments set `ENABLE_SCHEDULER=true`.
"""

import logging

from apscheduler.schedulers.background import BackgroundScheduler

from app.core.config import get_settings
from app.core.db import SessionLocal
from app.modules.sbom import service as sbom_service
from app.modules.waivers import service as waivers_service

logger = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None


def _run_dependency_track_sync() -> None:
    db = SessionLocal()
    try:
        result = sbom_service.sync_from_connector(db)
        logger.info(
            "Dependency-Track sync: %s projects, %s findings created, %s auto-closed, %s errors",
            result.projects_seen,
            result.findings_created,
            result.findings_auto_closed,
            len(result.errors),
        )
    finally:
        db.close()


def _run_stale_check() -> None:
    db = SessionLocal()
    try:
        result = sbom_service.check_stale_versions(db)
        logger.info(
            "Stale SBOM check: %s newly flagged, %s total stale",
            len(result.newly_flagged_version_ids),
            result.total_stale_versions,
        )
    finally:
        db.close()


def _run_waiver_expiry_check() -> None:
    db = SessionLocal()
    try:
        result = waivers_service.check_expired_waivers(db)
        logger.info(
            "Waiver expiry check: %s expired, %s findings reopened",
            result.expired_count,
            result.reopened_finding_count,
        )
    finally:
        db.close()


def start_scheduler() -> BackgroundScheduler | None:
    """Starts the background jobs if enabled. Returns the scheduler so `app.main` can
    shut it down cleanly, or None if scheduling is disabled."""
    global _scheduler
    settings = get_settings()
    if not settings.enable_scheduler:
        return None

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        _run_dependency_track_sync,
        "interval",
        hours=settings.sbom_sync_interval_hours,
        id="dependency_track_sync",
    )
    scheduler.add_job(
        _run_stale_check,
        "interval",
        hours=settings.stale_check_interval_hours,
        id="stale_sbom_check",
    )
    scheduler.add_job(
        _run_waiver_expiry_check,
        "interval",
        hours=settings.waiver_expiry_check_interval_hours,
        id="waiver_expiry_check",
    )
    scheduler.start()
    _scheduler = scheduler
    logger.info(
        "Background scheduler started: Dependency-Track sync every %sh, stale check every %sh, "
        "waiver expiry check every %sh",
        settings.sbom_sync_interval_hours,
        settings.stale_check_interval_hours,
        settings.waiver_expiry_check_interval_hours,
    )
    return scheduler


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
