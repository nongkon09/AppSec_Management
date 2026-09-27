import uuid
from datetime import date, datetime

from pydantic import BaseModel

from app.schemas.deployment import DeploymentOut
from app.schemas.risk_exception import ExceptionApprovalOut, ExceptionBypassOut


class EvidenceApplication(BaseModel):
    id: uuid.UUID
    name: str
    owner_team: str
    criticality: str
    internet_facing: bool


class EvidenceScanFinding(BaseModel):
    finding_id: uuid.UUID
    issue_key: str
    label: str
    severity_at_scan: str
    status_at_scan: str


class EvidenceScan(BaseModel):
    id: uuid.UUID
    version_label: str
    scanned_at: datetime
    is_manual_upload: bool
    uploaded_by: str | None
    source_tool: str | None
    image_digest: str | None
    commit_sha: str | None
    pipeline_run: str | None
    sca_bom_imported_at: datetime | None
    sbom_sha256: str | None
    sbom_available: bool
    # True for the last scan before the period of a version that was running during it.
    is_baseline: bool
    findings: list[EvidenceScanFinding]


class EvidenceException(BaseModel):
    reference: str
    exception_type: str
    status: str
    requested_by: str
    created_at: datetime
    reason: str
    original_severity_tier: str
    residual_severity_tier: str | None
    expires_on: date
    covered: list[str]
    controls: list[str]
    approvals: list[ExceptionApprovalOut]
    bypasses: list[ExceptionBypassOut]
    is_legacy: bool


class EvidencePack(BaseModel):
    application: EvidenceApplication
    period_from: date
    period_to: date
    generated_at: datetime
    generated_by: str
    deployments: list[DeploymentOut]
    scans: list[EvidenceScan]
    exceptions: list[EvidenceException]
