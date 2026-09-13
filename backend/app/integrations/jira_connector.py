"""Jira connector (Requirement.md FR-7.1) — Jira Cloud/Server REST API v2.

Authenticates with HTTP Basic Auth, where `auth_token` is stored as `"<email>:<api_token>"`
(Jira Cloud's own convention for API tokens; a Jira Server/Data Center Personal Access
Token can be used the same way with an empty email segment, `":<PAT>"`, since Jira accepts
a PAT as the Basic Auth password). `config` on the connector must supply `project_key`
(where issues are created) and may supply `issue_type` (default "Bug").
"""

import base64
import logging

import httpx

from app.integrations.ticket_connector import TicketDraft

logger = logging.getLogger(__name__)

DEFAULT_ISSUE_TYPE = "Bug"
# FR-7.5/7.6: our connector-agnostic resolution names, mapped to whichever Jira workflow
# transition is offered under that name. A workflow that renamed its transitions needs
# this mapping adjusted — Jira has no stable transition IDs across projects, only names.
_TRANSITION_NAME_CANDIDATES = {
    "done": ("Done", "Resolve Issue", "Closed", "Close Issue"),
    "wont_fix": ("Won't Fix", "Won't Do", "Rejected", "Closed"),
}


class JiraConnector:
    """`TicketConnector` implementation for Jira Cloud/Server."""

    def __init__(self, base_url: str, auth_token: str, config: dict) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_token = auth_token
        self._project_key = config.get("project_key")
        self._issue_type = config.get("issue_type", DEFAULT_ISSUE_TYPE)
        if not self._project_key:
            raise ValueError("Jira connector config is missing required 'project_key'")

    def _client(self) -> httpx.Client:
        basic = base64.b64encode(self._auth_token.encode()).decode("ascii")
        return httpx.Client(
            base_url=self._base_url,
            headers={
                "Authorization": f"Basic {basic}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=30.0,
        )

    def create_ticket(self, draft: TicketDraft) -> str:
        fields: dict = {
            "project": {"key": self._project_key},
            "summary": draft.summary,
            "description": f"{draft.description}\n\nAppSec Finding reference: {draft.reference}",
            "issuetype": {"name": self._issue_type},
        }
        if draft.due_date:
            fields["duedate"] = draft.due_date
        with self._client() as client:
            response = client.post("/rest/api/2/issue", json={"fields": fields})
            response.raise_for_status()
            return response.json()["key"]

    def attach_comment(self, external_id: str, comment: str) -> None:
        with self._client() as client:
            response = client.post(
                f"/rest/api/2/issue/{external_id}/comment", json={"body": comment}
            )
            response.raise_for_status()

    def update_ticket(self, external_id: str, *, comment: str | None = None) -> None:
        if comment:
            self.attach_comment(external_id, comment)

    def _find_transition_id(self, client: httpx.Client, external_id: str, resolution: str) -> str:
        candidates = _TRANSITION_NAME_CANDIDATES.get(resolution, (resolution,))
        response = client.get(f"/rest/api/2/issue/{external_id}/transitions")
        response.raise_for_status()
        available = {t["name"]: t["id"] for t in response.json().get("transitions", [])}
        for name in candidates:
            if name in available:
                return available[name]
        raise ValueError(
            f"No transition matching {resolution!r} is available on {external_id} "
            f"(workflow offers: {sorted(available)})"
        )

    def close_ticket(self, external_id: str, *, resolution: str, comment: str) -> None:
        with self._client() as client:
            transition_id = self._find_transition_id(client, external_id, resolution)
            payload = {
                "transition": {"id": transition_id},
                "update": {"comment": [{"add": {"body": comment}}]},
            }
            response = client.post(f"/rest/api/2/issue/{external_id}/transitions", json=payload)
            response.raise_for_status()

    def get_ticket_status(self, external_id: str) -> str:
        with self._client() as client:
            response = client.get(f"/rest/api/2/issue/{external_id}", params={"fields": "status"})
            response.raise_for_status()
            return response.json()["fields"]["status"]["name"]
