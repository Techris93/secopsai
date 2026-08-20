"""Approval-gated ticket proposals and provider adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


Requester = Callable[[str, str, dict[str, str], dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class TicketRequest:
    provider: str
    project: str
    title: str
    body: str
    finding_id: str
    approved: bool = False

    def validate(self) -> None:
        if self.provider not in {"github", "jira"}:
            raise ValueError("unsupported ticket provider")
        if not self.project or not self.title or not self.finding_id:
            raise ValueError("ticket project, title, and finding_id are required")


class GitHubIssueAdapter:
    def __init__(self, *, api_base: str = "https://api.github.com", requester: Requester | None = None) -> None:
        self.api_base = api_base.rstrip("/")
        self.requester = requester

    def create(self, request: TicketRequest) -> dict[str, Any]:
        request.validate()
        if request.provider != "github":
            raise ValueError("GitHub adapter received a non-GitHub request")
        if not request.approved:
            return {"status": "proposed", "provider": "github", "request": request.__dict__, "network_called": False}
        if self.requester is None:
            raise RuntimeError("GitHub requester is not configured")
        return self.requester("POST", f"{self.api_base}/repos/{request.project}/issues", {"Accept": "application/vnd.github+json"}, {"title": request.title[:300], "body": request.body[:10_000]})


class JiraIssueAdapter:
    def __init__(self, *, api_base: str, requester: Requester | None = None) -> None:
        self.api_base = api_base.rstrip("/")
        self.requester = requester

    def create(self, request: TicketRequest) -> dict[str, Any]:
        request.validate()
        if request.provider != "jira":
            raise ValueError("Jira adapter received a non-Jira request")
        if not request.approved:
            return {"status": "proposed", "provider": "jira", "request": request.__dict__, "network_called": False}
        if self.requester is None:
            raise RuntimeError("Jira requester is not configured")
        return self.requester("POST", f"{self.api_base}/rest/api/3/issue", {"Accept": "application/json"}, {"fields": {"project": {"key": request.project}, "summary": request.title[:300], "description": request.body[:10_000], "issuetype": {"name": "Task"}}})
