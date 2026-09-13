"""Import all ORM models here so Alembic's autogenerate (and Base.metadata.create_all
in tests) can discover every mapped table via app.core.db.Base."""

from app.models.audit import AuditLog
from app.models.component import Component
from app.models.finding import Finding
from app.models.integration import IntegrationConnector
from app.models.inventory import Application, AppVersion
from app.models.pentest import GoLiveApproval, PentestProject
from app.models.policy import PolicySet
from app.models.scan_result import ScanResult
from app.models.ticket import Ticket
from app.models.user import User
from app.models.waiver import Waiver

__all__ = [
    "AuditLog",
    "Component",
    "Finding",
    "IntegrationConnector",
    "Application",
    "AppVersion",
    "GoLiveApproval",
    "PentestProject",
    "PolicySet",
    "ScanResult",
    "Ticket",
    "User",
    "Waiver",
]
