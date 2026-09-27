"""Background jobs (Requirement.md FR-3.1 pull-sync cadence, FR-2.4 staleness sweep).

Guarded by `settings.enable_scheduler` (default off) so importing `app.main` — as every
test does — never starts a background job or opens an unwanted connection to the SCA
platform. Real deployments set `ENABLE_SCHEDULER=true`.
"""

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import BaseScheduler
from apscheduler.schedulers.blocking import BlockingScheduler

from app.core.config import get_settings
from app.core.db import SessionLocal
from app.modules.exceptions import service as exceptions_service
from app.modules.sbom import service as sbom_service

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


def run_exception_sweep() -> None:
    db = SessionLocal()
    try:
        expired, closed, flagged = exceptions_service.sweep(db)
        logger.info(
            "Exception sweep: %s expired, %s closed, %s flagged for review",
            expired,
            closed,
            flagged,
        )
    finally:
        db.close()


def add_jobs(scheduler: BaseScheduler) -> None:
    settings = get_settings()
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
        run_exception_sweep,
        "interval",
        hours=settings.exception_sweep_interval_hours,
        id="exception_sweep",
    )
    logger.info(
        "Background jobs: Dependency-Track sync every %sh, stale check every %sh, "
        "exception sweep every %sh",
        settings.sbom_sync_interval_hours,
        settings.stale_check_interval_hours,
        settings.exception_sweep_interval_hours,
    )


def start_scheduler() -> BackgroundScheduler | None:
    """Starts the background jobs inside the API process if enabled. Returns the scheduler
    so `app.main` can shut it down cleanly, or None if scheduling is disabled.

    Only for single-process setups: every uvicorn worker runs its own copy, so a
    multi-worker API would sync and sweep once per worker. Production runs the jobs in
    the dedicated `app.worker` process instead and leaves this off.
    """
    global _scheduler
    if not get_settings().enable_scheduler:
        return None

    scheduler = BackgroundScheduler()
    add_jobs(scheduler)
    scheduler.start()
    _scheduler = scheduler
    return scheduler


def run_blocking() -> None:
    """Runs the jobs in the foreground until the process is stopped (`app.worker`)."""
    scheduler = BlockingScheduler()
    add_jobs(scheduler)
    scheduler.start()


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
