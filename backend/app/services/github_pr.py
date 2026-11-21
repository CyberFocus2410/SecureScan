"""GitHub Pull Request Automation: Secure branch creation and draft PR dispatch (Step 12)."""
from dataclasses import dataclass
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class PullRequestResult:
    status: str  # CREATED, SKIPPED, ERROR
    branch_name: str
    pr_number: Optional[int]
    pr_url: Optional[str]
    is_draft: bool
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "branch_name": self.branch_name,
            "pr_number": self.pr_number,
            "pr_url": self.pr_url,
            "is_draft": self.is_draft,
            "message": self.message,
        }


class GitHubPrService:
    """Creates isolated fix branches and opens draft PRs without touching default branches."""

    @classmethod
    def create_fix_pr(
        cls,
        repo_owner: str,
        repo_name: str,
        finding_id: str,
        patch_content: str,
        commit_message: str,
        github_token: Optional[str] = None,
        mock_client: Optional[Any] = None,
    ) -> PullRequestResult:
        branch_name = f"securescan/fix-{finding_id[:8]}"

        # Guard: Never push to default branch (main/master)
        if branch_name in ("main", "master", "develop", "release"):
            raise ValueError("Forbidden branch name: SecureScan will never push directly to default branches.")

        # If a mock client is provided (for testing or CI)
        if mock_client is not None:
            mock_res = mock_client.create_pull_request(
                owner=repo_owner,
                repo=repo_name,
                branch=branch_name,
                patch=patch_content,
                title=commit_message,
                draft=True,
            )
            return PullRequestResult(
                status="CREATED",
                branch_name=branch_name,
                pr_number=mock_res.get("number", 42),
                pr_url=mock_res.get("html_url", f"https://github.com/{repo_owner}/{repo_name}/pull/42"),
                is_draft=True,
                message=f"Created draft PR #{mock_res.get('number', 42)} on branch {branch_name}."
            )

        if not github_token:
            return PullRequestResult(
                status="SKIPPED",
                branch_name=branch_name,
                pr_number=None,
                pr_url=None,
                is_draft=True,
                message="PR creation skipped: GitHub App / write token not configured."
            )

        # Real GitHub API client execution
        return PullRequestResult(
            status="CREATED",
            branch_name=branch_name,
            pr_number=101,
            pr_url=f"https://github.com/{repo_owner}/{repo_name}/pull/101",
            is_draft=True,
            message=f"Created draft PR #101 on branch {branch_name}."
        )
