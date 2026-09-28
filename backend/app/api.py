from fastapi import APIRouter

from app.modules.audit.router import router as audit_router
from app.modules.auth.router import router as auth_router
from app.modules.controls.router import router as controls_router
from app.modules.deployments.router import router as deployments_router
from app.modules.directory.router import router as directory_router
from app.modules.directory.scim import router as scim_router
from app.modules.evidence.router import router as evidence_router
from app.modules.exceptions.router import router as exceptions_router
from app.modules.findings.router import router as findings_router
from app.modules.golive.router import router as golive_router
from app.modules.integrations.router import router as integrations_router
from app.modules.inventory.router import router as inventory_router
from app.modules.pentest.router import router as pentest_router
from app.modules.policy.router import router as policy_router
from app.modules.reports.router import router as reports_router
from app.modules.sbom.router import router as sbom_router
from app.modules.users.router import router as users_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth_router)
api_router.include_router(inventory_router)
api_router.include_router(policy_router)
api_router.include_router(findings_router)
api_router.include_router(audit_router)
api_router.include_router(sbom_router)
api_router.include_router(users_router)
api_router.include_router(integrations_router)
api_router.include_router(golive_router)
api_router.include_router(pentest_router)
api_router.include_router(deployments_router)
api_router.include_router(exceptions_router)
api_router.include_router(controls_router)
api_router.include_router(evidence_router)
api_router.include_router(reports_router)
api_router.include_router(directory_router)
api_router.include_router(scim_router)
