"""Builds the right `TicketConnector` for a configured `IntegrationConnector` row.

Jira is the one connector type with a real, working implementation in this codebase
(`JiraConnector`) — it is the flagship destination named in FR-7.1. ManageEngine
ServiceDesk Plus and a generic webhook are declared `ConnectorType` values so Admin can
already register them as configuration (FR-7's "Admin เพิ่ม/ตั้งค่า ITSM ปลายทางใหม่ได้ใน
อนาคตโดยไม่ต้องแก้ Core"), but calling one raises clearly rather than silently no-op'ing —
adding their real implementations is future work, not a hidden gap.
"""

from app.integrations.jira_connector import JiraConnector
from app.integrations.ticket_connector import TicketConnector
from app.models.integration import ConnectorType, IntegrationConnector


class ConnectorNotImplementedError(NotImplementedError):
    pass


def build_connector(connector: IntegrationConnector) -> TicketConnector:
    if connector.connector_type == ConnectorType.JIRA:
        return JiraConnector(connector.base_url, connector.auth_token, connector.config)
    raise ConnectorNotImplementedError(
        f"{connector.connector_type.value} has no working connector implementation yet "
        "— only 'jira' does. Registering it as configuration is supported; calling it is not."
    )
