"""
GitHub Integration Module

This module provides functions to interact with GitHub API for:
- Creating and managing pull requests
- Opening and closing issues
- Adding comments to PRs and issues
- Authentication and error handling

Requirements:
- PyGithub library
- GitHub personal access token
"""

import os
import logging
from typing import Optional, Dict, Any, List
from github import Github, GithubException
from github.PullRequest import PullRequest
from github.Issue import Issue
from github.Repository import Repository
from github.Branch import Branch
from github.Comparison import Comparison

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GitHubIntegration:
    """GitHub integration class for managing pull requests and issues."""
    
    def __init__(self, token: Optional[str] = None):
        """
        Initialize GitHub integration.
        
        Args:
            token: GitHub personal access token. If None, will try to get from GITHUB_TOKEN env var.
        """
        self.token = token or os.getenv('GITHUB_TOKEN')
        if not self.token:
            raise ValueError("GitHub token is required. Set GITHUB_TOKEN env var or pass token parameter.")
        
        self.github = Github(self.token)
        self.user = self.github.get_user()
        logger.info(f"GitHub integration initialized for user: {self.user.login}")
    
    def get_repository(self, repo_name: str) -> Repository:
        """
        Get repository object.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            
        Returns:
            Repository object
        """
        try:
            return self.github.get_repo(repo_name)
        except GithubException as e:
            logger.error(f"Failed to get repository {repo_name}: {e}")
            raise
    
    # Pull Request Functions
    
    def create_pull_request(
        self,
        repo_name: str,
        title: str,
        body: str,
        head: str,
        base: str = "main",
        draft: bool = False
    ) -> PullRequest:
        """
        Create a new pull request.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            title: PR title
            body: PR description
            head: Source branch name
            base: Target branch name (default: main)
            draft: Whether to create as draft PR
            
        Returns:
            Created PullRequest object
        """
        try:
            repo = self.get_repository(repo_name)
            pr = repo.create_pull(
                title=title,
                body=body,
                head=head,
                base=base,
                draft=draft
            )
            logger.info(f"Created PR #{pr.number}: {title}")
            return pr
        except GithubException as e:
            logger.error(f"Failed to create PR: {e}")
            raise
    
    def get_pull_request(self, repo_name: str, pr_number: int) -> PullRequest:
        """
        Get a pull request by number.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            pr_number: Pull request number
            
        Returns:
            PullRequest object
        """
        try:
            repo = self.get_repository(repo_name)
            return repo.get_pull(pr_number)
        except GithubException as e:
            logger.error(f"Failed to get PR #{pr_number}: {e}")
            raise
    
    def list_pull_requests(
        self,
        repo_name: str,
        state: str = "open",
        head: Optional[str] = None,
        base: Optional[str] = None
    ) -> List[PullRequest]:
        """
        List pull requests in a repository.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            state: PR state ('open', 'closed', 'all')
            head: Filter by source branch
            base: Filter by target branch
            
        Returns:
            List of PullRequest objects
        """
        try:
            repo = self.get_repository(repo_name)
            prs = repo.get_pulls(state=state, head=head, base=base)
            return list(prs)
        except GithubException as e:
            logger.error(f"Failed to list PRs: {e}")
            raise
    
    def comment_on_pull_request(
        self,
        repo_name: str,
        pr_number: int,
        comment: str
    ) -> None:
        """
        Add a comment to a pull request.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            pr_number: Pull request number
            comment: Comment text
        """
        try:
            pr = self.get_pull_request(repo_name, pr_number)
            pr.create_issue_comment(comment)
            logger.info(f"Added comment to PR #{pr_number}")
        except GithubException as e:
            logger.error(f"Failed to comment on PR #{pr_number}: {e}")
            raise
    
    def merge_pull_request(
        self,
        repo_name: str,
        pr_number: int,
        merge_method: str = "merge",
        commit_title: Optional[str] = None,
        commit_message: Optional[str] = None
    ) -> bool:
        """
        Merge a pull request.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            pr_number: Pull request number
            merge_method: Merge method ('merge', 'squash', 'rebase')
            commit_title: Custom commit title
            commit_message: Custom commit message
            
        Returns:
            True if merged successfully
        """
        try:
            pr = self.get_pull_request(repo_name, pr_number)
            result = pr.merge(
                commit_title=commit_title,
                commit_message=commit_message,
                merge_method=merge_method
            )
            if result.merged:
                logger.info(f"Merged PR #{pr_number}")
                return True
            else:
                logger.warning(f"PR #{pr_number} merge failed: {result.message}")
                return False
        except GithubException as e:
            logger.error(f"Failed to merge PR #{pr_number}: {e}")
            raise
    
    def close_pull_request(self, repo_name: str, pr_number: int) -> None:
        """
        Close a pull request.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            pr_number: Pull request number
        """
        try:
            pr = self.get_pull_request(repo_name, pr_number)
            pr.edit(state="closed")
            logger.info(f"Closed PR #{pr_number}")
        except GithubException as e:
            logger.error(f"Failed to close PR #{pr_number}: {e}")
            raise
    
    # Issue Functions
    
    def create_issue(
        self,
        repo_name: str,
        title: str,
        body: str = "",
        labels: Optional[List[str]] = None,
        assignees: Optional[List[str]] = None
    ) -> Issue:
        """
        Create a new issue.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            title: Issue title
            body: Issue description
            labels: List of label names
            assignees: List of usernames to assign
            
        Returns:
            Created Issue object
        """
        try:
            repo = self.get_repository(repo_name)
            issue = repo.create_issue(
                title=title,
                body=body,
                labels=labels or [],
                assignees=assignees or []
            )
            logger.info(f"Created issue #{issue.number}: {title}")
            return issue
        except GithubException as e:
            logger.error(f"Failed to create issue: {e}")
            raise
    
    def get_issue(self, repo_name: str, issue_number: int) -> Issue:
        """
        Get an issue by number.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            issue_number: Issue number
            
        Returns:
            Issue object
        """
        try:
            repo = self.get_repository(repo_name)
            return repo.get_issue(issue_number)
        except GithubException as e:
            logger.error(f"Failed to get issue #{issue_number}: {e}")
            raise
    
    def list_issues(
        self,
        repo_name: str,
        state: str = "open",
        labels: Optional[List[str]] = None,
        assignee: Optional[str] = None
    ) -> List[Issue]:
        """
        List issues in a repository.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            state: Issue state ('open', 'closed', 'all')
            labels: Filter by labels
            assignee: Filter by assignee
            
        Returns:
            List of Issue objects
        """
        try:
            repo = self.get_repository(repo_name)
            issues = repo.get_issues(
                state=state,
                labels=labels,
                assignee=assignee
            )
            return list(issues)
        except GithubException as e:
            logger.error(f"Failed to list issues: {e}")
            raise
    
    def comment_on_issue(
        self,
        repo_name: str,
        issue_number: int,
        comment: str
    ) -> None:
        """
        Add a comment to an issue.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            issue_number: Issue number
            comment: Comment text
        """
        try:
            issue = self.get_issue(repo_name, issue_number)
            issue.create_comment(comment)
            logger.info(f"Added comment to issue #{issue_number}")
        except GithubException as e:
            logger.error(f"Failed to comment on issue #{issue_number}: {e}")
            raise
    
    def close_issue(self, repo_name: str, issue_number: int) -> None:
        """
        Close an issue.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            issue_number: Issue number
        """
        try:
            issue = self.get_issue(repo_name, issue_number)
            issue.edit(state="closed")
            logger.info(f"Closed issue #{issue_number}")
        except GithubException as e:
            logger.error(f"Failed to close issue #{issue_number}: {e}")
            raise
    
    def reopen_issue(self, repo_name: str, issue_number: int) -> None:
        """
        Reopen a closed issue.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            issue_number: Issue number
        """
        try:
            issue = self.get_issue(repo_name, issue_number)
            issue.edit(state="open")
            logger.info(f"Reopened issue #{issue_number}")
        except GithubException as e:
            logger.error(f"Failed to reopen issue #{issue_number}: {e}")
            raise
    
    def add_labels_to_issue(
        self,
        repo_name: str,
        issue_number: int,
        labels: List[str]
    ) -> None:
        """
        Add labels to an issue.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            issue_number: Issue number
            labels: List of label names
        """
        try:
            issue = self.get_issue(repo_name, issue_number)
            issue.add_to_labels(*labels)
            logger.info(f"Added labels {labels} to issue #{issue_number}")
        except GithubException as e:
            logger.error(f"Failed to add labels to issue #{issue_number}: {e}")
            raise
    
    def assign_issue(
        self,
        repo_name: str,
        issue_number: int,
        assignees: List[str]
    ) -> None:
        """
        Assign users to an issue.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            issue_number: Issue number
            assignees: List of usernames to assign
        """
        try:
            issue = self.get_issue(repo_name, issue_number)
            issue.add_to_assignees(*assignees)
            logger.info(f"Assigned {assignees} to issue #{issue_number}")
        except GithubException as e:
            logger.error(f"Failed to assign issue #{issue_number}: {e}")
            raise
    
    # Branch Functions
    
    def create_branch(
        self,
        repo_name: str,
        branch_name: str,
        source_branch: str = "main",
        sha: Optional[str] = None
    ) -> Branch:
        """
        Create a new branch from an existing branch or commit.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            branch_name: Name of the new branch
            source_branch: Source branch to create from (default: main)
            sha: Specific commit SHA to create from (optional)
            
        Returns:
            Created Branch object
        """
        try:
            repo = self.get_repository(repo_name)
            
            # Get the source branch or commit
            if sha:
                source_ref = repo.get_git_ref(f"heads/{source_branch}")
                source_sha = source_ref.object.sha
            else:
                source_ref = repo.get_git_ref(f"heads/{source_branch}")
                source_sha = source_ref.object.sha
            
            # Create the new branch
            new_ref = repo.create_git_ref(f"refs/heads/{branch_name}", source_sha)
            branch = repo.get_branch(branch_name)
            
            logger.info(f"Created branch '{branch_name}' from '{source_branch}'")
            return branch
        except GithubException as e:
            logger.error(f"Failed to create branch '{branch_name}': {e}")
            raise
    
    def get_branch(self, repo_name: str, branch_name: str) -> Branch:
        """
        Get a branch by name.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            branch_name: Name of the branch
            
        Returns:
            Branch object
        """
        try:
            repo = self.get_repository(repo_name)
            return repo.get_branch(branch_name)
        except GithubException as e:
            logger.error(f"Failed to get branch '{branch_name}': {e}")
            raise
    
    def list_branches(
        self,
        repo_name: str,
        protected: Optional[bool] = None
    ) -> List[Branch]:
        """
        List all branches in a repository.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            protected: Filter by protection status (True/False/None for all)
            
        Returns:
            List of Branch objects
        """
        try:
            repo = self.get_repository(repo_name)
            branches = repo.get_branches()
            
            if protected is not None:
                filtered_branches = []
                for branch in branches:
                    try:
                        # Check if branch is protected
                        is_protected = branch.protected
                        if (protected and is_protected) or (not protected and not is_protected):
                            filtered_branches.append(branch)
                    except GithubException:
                        # If we can't determine protection status, include it
                        if protected is None:
                            filtered_branches.append(branch)
                return filtered_branches
            
            return list(branches)
        except GithubException as e:
            logger.error(f"Failed to list branches: {e}")
            raise
    
    def delete_branch(self, repo_name: str, branch_name: str) -> None:
        """
        Delete a branch.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            branch_name: Name of the branch to delete
        """
        try:
            repo = self.get_repository(repo_name)
            ref = repo.get_git_ref(f"heads/{branch_name}")
            ref.delete()
            logger.info(f"Deleted branch '{branch_name}'")
        except GithubException as e:
            logger.error(f"Failed to delete branch '{branch_name}': {e}")
            raise
    
    def compare_branches(
        self,
        repo_name: str,
        base: str,
        head: str
    ) -> Comparison:
        """
        Compare two branches and get the differences.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            base: Base branch name
            head: Head branch name
            
        Returns:
            Comparison object with differences
        """
        try:
            repo = self.get_repository(repo_name)
            comparison = repo.compare(base, head)
            logger.info(f"Compared branches '{base}' and '{head}'")
            return comparison
        except GithubException as e:
            logger.error(f"Failed to compare branches '{base}' and '{head}': {e}")
            raise
    
    def merge_branch(
        self,
        repo_name: str,
        base: str,
        head: str,
        commit_message: Optional[str] = None
    ) -> bool:
        """
        Merge one branch into another.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            base: Target branch name
            head: Source branch name
            commit_message: Custom merge commit message
            
        Returns:
            True if merge was successful
        """
        try:
            repo = self.get_repository(repo_name)
            base_branch = repo.get_branch(base)
            head_branch = repo.get_branch(head)
            
            # Create merge commit
            merge_commit = repo.merge(
                base,
                head_branch.commit.sha,
                commit_message or f"Merge branch '{head}' into '{base}'"
            )
            
            if merge_commit.merged:
                logger.info(f"Successfully merged '{head}' into '{base}'")
                return True
            else:
                logger.warning(f"Merge failed: {merge_commit.message}")
                return False
        except GithubException as e:
            logger.error(f"Failed to merge '{head}' into '{base}': {e}")
            raise
    
    def get_branch_protection(self, repo_name: str, branch_name: str) -> Dict[str, Any]:
        """
        Get branch protection rules.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            branch_name: Name of the branch
            
        Returns:
            Dictionary containing protection rules
        """
        try:
            repo = self.get_repository(repo_name)
            protection = repo.get_branch_protection(branch_name)
            
            protection_info = {
                "required_status_checks": protection.required_status_checks,
                "enforce_admins": protection.enforce_admins,
                "required_pull_request_reviews": protection.required_pull_request_reviews,
                "restrictions": protection.restrictions,
                "allow_force_pushes": protection.allow_force_pushes,
                "allow_deletions": protection.allow_deletions
            }
            
            logger.info(f"Retrieved protection rules for branch '{branch_name}'")
            return protection_info
        except GithubException as e:
            logger.error(f"Failed to get protection rules for branch '{branch_name}': {e}")
            raise
    
    def set_branch_protection(
        self,
        repo_name: str,
        branch_name: str,
        required_status_checks: Optional[Dict[str, Any]] = None,
        enforce_admins: bool = False,
        required_pull_request_reviews: Optional[Dict[str, Any]] = None,
        restrictions: Optional[Dict[str, Any]] = None,
        allow_force_pushes: bool = False,
        allow_deletions: bool = False
    ) -> None:
        """
        Set branch protection rules.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            branch_name: Name of the branch
            required_status_checks: Status checks configuration
            enforce_admins: Whether to enforce rules for admins
            required_pull_request_reviews: PR review requirements
            restrictions: User/team restrictions
            allow_force_pushes: Whether to allow force pushes
            allow_deletions: Whether to allow deletions
        """
        try:
            repo = self.get_repository(repo_name)
            
            # Build protection rule
            protection_rule = {
                "required_status_checks": required_status_checks,
                "enforce_admins": enforce_admins,
                "required_pull_request_reviews": required_pull_request_reviews,
                "restrictions": restrictions,
                "allow_force_pushes": allow_force_pushes,
                "allow_deletions": allow_deletions
            }
            
            # Remove None values
            protection_rule = {k: v for k, v in protection_rule.items() if v is not None}
            
            repo.edit_branch_protection(branch_name, **protection_rule)
            logger.info(f"Set protection rules for branch '{branch_name}'")
        except GithubException as e:
            logger.error(f"Failed to set protection rules for branch '{branch_name}': {e}")
            raise
    
    def remove_branch_protection(self, repo_name: str, branch_name: str) -> None:
        """
        Remove branch protection rules.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            branch_name: Name of the branch
        """
        try:
            repo = self.get_repository(repo_name)
            repo.remove_branch_protection(branch_name)
            logger.info(f"Removed protection rules for branch '{branch_name}'")
        except GithubException as e:
            logger.error(f"Failed to remove protection rules for branch '{branch_name}': {e}")
            raise
    
    def get_branch_commits(
        self,
        repo_name: str,
        branch_name: str,
        since: Optional[str] = None,
        until: Optional[str] = None
    ) -> List[Any]:
        """
        Get commits from a specific branch.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            branch_name: Name of the branch
            since: Only commits after this date (ISO 8601 format)
            until: Only commits before this date (ISO 8601 format)
            
        Returns:
            List of commit objects
        """
        try:
            repo = self.get_repository(repo_name)
            branch = repo.get_branch(branch_name)
            
            # Get commits from the branch
            commits = repo.get_commits(
                sha=branch.commit.sha,
                since=since,
                until=until
            )
            
            logger.info(f"Retrieved commits from branch '{branch_name}'")
            return list(commits)
        except GithubException as e:
            logger.error(f"Failed to get commits from branch '{branch_name}': {e}")
            raise
    
    def rename_branch(
        self,
        repo_name: str,
        old_name: str,
        new_name: str
    ) -> Branch:
        """
        Rename a branch by creating a new branch and deleting the old one.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            old_name: Current branch name
            new_name: New branch name
            
        Returns:
            New Branch object
        """
        try:
            # Get the old branch
            old_branch = self.get_branch(repo_name, old_name)
            
            # Create new branch with the same commit
            new_branch = self.create_branch(
                repo_name,
                new_name,
                sha=old_branch.commit.sha
            )
            
            # Delete the old branch
            self.delete_branch(repo_name, old_name)
            
            logger.info(f"Renamed branch '{old_name}' to '{new_name}'")
            return new_branch
        except GithubException as e:
            logger.error(f"Failed to rename branch '{old_name}' to '{new_name}': {e}")
            raise


# Convenience functions for direct usage
def create_github_integration(token: Optional[str] = None) -> GitHubIntegration:
    """
    Create a GitHub integration instance.
    
    Args:
        token: GitHub personal access token
        
    Returns:
        GitHubIntegration instance
    """
    return GitHubIntegration(token)


# Example usage functions
def example_usage():
    """Example usage of the GitHub integration functions."""
    
    # Initialize (make sure to set GITHUB_TOKEN environment variable)
    try:
        gh = create_github_integration()
        repo_name = "your-username/your-repo"
        
        # Create a pull request
        pr = gh.create_pull_request(
            repo_name=repo_name,
            title="Add new feature",
            body="This PR adds a new feature to the project.",
            head="feature-branch",
            base="main"
        )
        print(f"Created PR #{pr.number}")
        
        # Comment on the PR
        gh.comment_on_pull_request(
            repo_name=repo_name,
            pr_number=pr.number,
            comment="Great work! This looks good to me."
        )
        
        # Create an issue
        issue = gh.create_issue(
            repo_name=repo_name,
            title="Bug: Something is broken",
            body="Describe the bug here...",
            labels=["bug", "high-priority"],
            assignees=["username"]
        )
        print(f"Created issue #{issue.number}")
        
        # Comment on the issue
        gh.comment_on_issue(
            repo_name=repo_name,
            issue_number=issue.number,
            comment="I'll look into this issue."
        )
        
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    example_usage()
