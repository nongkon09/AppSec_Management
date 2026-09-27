import uuid
from datetime import date, datetime

from pydantic import BaseModel, Field


class ManualSbomUploadResult(BaseModel):
    """Response for FR-2.6.1 manual/COTS SBOM upload."""

    app_version_id: uuid.UUID
    sbom_format: str
    components_ingested: int
    forwarded_to_sca_platform: bool
    forward_error: str | None = None


class DependencyTrackSyncResult(BaseModel):
    """Response for a triggered FR-2.5/FR-3 pull-sync from the SCA platform."""

    projects_seen: int
    applications_auto_created: int
    components_upserted: int
    findings_created: int
    findings_auto_closed: int
    errors: list[str] = Field(default_factory=list)


class StaleCheckResult(BaseModel):
    """Response for a triggered FR-2.4 staleness sweep."""

    newly_flagged_version_ids: list[uuid.UUID]
    total_stale_versions: int


class IngestionHistoryOut(BaseModel):
    """One row of FR-2.3 ingestion history (backed by ScanResult)."""

    id: uuid.UUID
    scan_type: str
    scanned_at: datetime
    result_status: str
    is_manual_upload: bool
    uploaded_by: str | None
    report_file_url: str | None
    validity_expiry_date: date | None
    source_tool: str | None
    image_digest: str | None
    commit_sha: str | None
    pipeline_run: str | None
    sca_bom_imported_at: datetime | None
    sbom_sha256: str | None

    model_config = {"from_attributes": True}
