"""Pluggable ITSM connector interface (Requirement.md FR-7, Section 10.2's `ITicketConnector`).

FR-7's header note requires this to be "Integration/Connector Framework แบบ Pluggable":
Admin adds a new ITSM destination by writing one new `TicketConnector` implementation and
registering a `ConnectorType`, without touching the routing/auto-close logic in
`app.modules.integrations.service` — the same shape as `SCAConnector` for FR-2.5.
"""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class TicketDraft:
    """Everything FR-7.3 requires on ticket creation, already assembled by the caller so
    every connector implementation renders the same content the same way."""

    summary: str
    description: str
    due_date: str | None  # ISO date, or None for a best-effort Finding (no SLA date)
    reference: str  # our Finding ID, for the connector to embed as a back-reference


class TicketConnector(Protocol):
    """Section 10.2: `createTicket()`, `updateTicket()`, `closeTicket()`,
    `getTicketStatus()`, `attachComment()`."""

    def create_ticket(self, draft: TicketDraft) -> str:
        """Returns the destination's external ticket ID (e.g. a Jira issue key)."""
        ...

    def attach_comment(self, external_id: str, comment: str) -> None: ...

    def update_ticket(self, external_id: str, *, comment: str | None = None) -> None: ...

    def close_ticket(self, external_id: str, *, resolution: str, comment: str) -> None:
        """FR-7.5/7.6: `resolution` is a connector-native transition name — Jira's
        "Done", an ITSM's "Resolved", etc. — the connector maps it to whatever its own
        workflow calls that state."""
        ...

    def get_ticket_status(self, external_id: str) -> str: ...
