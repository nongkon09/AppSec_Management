"""Import all ORM models here so Alembic's autogenerate (and Base.metadata.create_all
in tests) can discover every mapped table via app.core.db.Base."""

from app.models.audit import AuditLog
from app.models.component import Component
from app.models.deployment import Deployment
from app.models.directory import DirectoryGroup, DirectoryGroupMember, RoleMapping
from app.models.finding import Finding
from app.models.integration import IntegrationConnector
from app.models.inventory import Application, AppVersion
from app.models.pentest import GoLiveApproval, PentestProject
from app.models.policy import PolicySet
from app.models.risk_exception import (
    ExceptionApproval,
    ExceptionBypass,
    ExceptionItem,
    RiskException,
)
from app.models.scan_result import ScanFinding, ScanResult
from app.models.security_control import SecurityControl
from app.models.ticket import Ticket
from app.models.user import User

__all__ = [
    "AuditLog",
    "Component",
    "Deployment",
    "DirectoryGroup",
    "DirectoryGroupMember",
    "RoleMapping",
    "Finding",
    "IntegrationConnector",
    "Application",
    "AppVersion",
    "GoLiveApproval",
    "PentestProject",
    "PolicySet",
    "RiskException",
    "ExceptionItem",
    "ExceptionApproval",
    "ExceptionBypass",
    "ScanResult",
    "ScanFinding",
    "SecurityControl",
    "Ticket",
    "User",
]
