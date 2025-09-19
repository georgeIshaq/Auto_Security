# Auto_Security

A Python module for GitHub integration that provides functions to create pull requests, manage issues, and interact with the GitHub API.

## Features

### Pull Request Management
- ✅ Create pull requests
- ✅ Get pull request details
- ✅ List pull requests with filtering
- ✅ Comment on pull requests
- ✅ Merge pull requests
- ✅ Close pull requests

### Issue Management
- ✅ Create issues
- ✅ Get issue details
- ✅ List issues with filtering
- ✅ Comment on issues
- ✅ Close issues
- ✅ Reopen issues
- ✅ Add labels to issues
- ✅ Assign users to issues

### Branch Management
- ✅ Create branches
- ✅ Get branch details
- ✅ List branches with filtering
- ✅ Delete branches
- ✅ Compare branches
- ✅ Merge branches
- ✅ Rename branches
- ✅ Get branch commits
- ✅ Set branch protection rules
- ✅ Get branch protection info
- ✅ Remove branch protection

## Installation

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Set up your GitHub personal access token:
```bash
export GITHUB_TOKEN=your_github_token_here
```

## Quick Start

```python
from github_integration import create_github_integration

# Initialize GitHub integration
gh = create_github_integration()

# Create a pull request
pr = gh.create_pull_request(
    repo_name="username/repository",
    title="Add new feature",
    body="Description of changes",
    head="feature-branch",
    base="main"
)

# Create an issue
issue = gh.create_issue(
    repo_name="username/repository",
    title="Bug report",
    body="Description of the issue",
    labels=["bug", "high-priority"]
)

# Comment on PR or issue
gh.comment_on_pull_request("username/repository", pr.number, "Great work!")
gh.comment_on_issue("username/repository", issue.number, "I'll look into this.")

# Branch operations
branch = gh.create_branch("username/repository", "feature/new-feature", "main")
branches = gh.list_branches("username/repository")
gh.delete_branch("username/repository", "feature/new-feature")
```

## Usage Examples

### Pull Request Operations

```python
# Create a pull request
pr = gh.create_pull_request(
    repo_name="owner/repo",
    title="Feature: Add authentication",
    body="This PR adds user authentication functionality.",
    head="auth-feature",
    base="main",
    draft=False
)

# List open pull requests
open_prs = gh.list_pull_requests("owner/repo", state="open")

# Comment on a pull request
gh.comment_on_pull_request("owner/repo", pr.number, "LGTM! 👍")

# Merge a pull request
success = gh.merge_pull_request("owner/repo", pr.number, merge_method="squash")

# Close a pull request
gh.close_pull_request("owner/repo", pr.number)
```

### Issue Operations

```python
# Create an issue
issue = gh.create_issue(
    repo_name="owner/repo",
    title="Bug: Login not working",
    body="Users cannot log in with valid credentials.",
    labels=["bug", "critical"],
    assignees=["developer1"]
)

# List issues
open_issues = gh.list_issues("owner/repo", state="open")
bug_issues = gh.list_issues("owner/repo", labels=["bug"])

# Comment on an issue
gh.comment_on_issue("owner/repo", issue.number, "I'll investigate this.")

# Add labels to an issue
gh.add_labels_to_issue("owner/repo", issue.number, ["needs-review", "priority-high"])

# Assign users to an issue
gh.assign_issue("owner/repo", issue.number, ["developer2", "developer3"])

# Close an issue
gh.close_issue("owner/repo", issue.number)

# Reopen an issue
gh.reopen_issue("owner/repo", issue.number)
```

### Branch Operations

```python
# Create a branch
branch = gh.create_branch(
    repo_name="owner/repo",
    branch_name="feature/new-feature",
    source_branch="main"
)

# List branches
all_branches = gh.list_branches("owner/repo")
protected_branches = gh.list_branches("owner/repo", protected=True)

# Get branch details
branch = gh.get_branch("owner/repo", "feature/new-feature")

# Compare branches
comparison = gh.compare_branches("owner/repo", "main", "feature/new-feature")
print(f"Ahead by {comparison.ahead_by} commits")

# Get commits from a branch
commits = gh.get_branch_commits("owner/repo", "feature/new-feature")

# Merge branches
success = gh.merge_branch("owner/repo", "main", "feature/new-feature")

# Rename a branch
new_branch = gh.rename_branch("owner/repo", "old-name", "new-name")

# Set branch protection
gh.set_branch_protection(
    repo_name="owner/repo",
    branch_name="main",
    required_status_checks={"strict": True, "contexts": ["ci/tests"]},
    enforce_admins=True,
    required_pull_request_reviews={"required_approving_review_count": 2}
)

# Get branch protection info
protection = gh.get_branch_protection("owner/repo", "main")

# Remove branch protection
gh.remove_branch_protection("owner/repo", "main")

# Delete a branch
gh.delete_branch("owner/repo", "feature/new-feature")
```

## API Reference

### GitHubIntegration Class

#### Constructor
```python
GitHubIntegration(token: Optional[str] = None)
```
- `token`: GitHub personal access token. If None, will try to get from `GITHUB_TOKEN` environment variable.

#### Pull Request Methods

- `create_pull_request(repo_name, title, body, head, base="main", draft=False)`
- `get_pull_request(repo_name, pr_number)`
- `list_pull_requests(repo_name, state="open", head=None, base=None)`
- `comment_on_pull_request(repo_name, pr_number, comment)`
- `merge_pull_request(repo_name, pr_number, merge_method="merge", commit_title=None, commit_message=None)`
- `close_pull_request(repo_name, pr_number)`

#### Issue Methods

- `create_issue(repo_name, title, body="", labels=None, assignees=None)`
- `get_issue(repo_name, issue_number)`
- `list_issues(repo_name, state="open", labels=None, assignee=None)`
- `comment_on_issue(repo_name, issue_number, comment)`
- `close_issue(repo_name, issue_number)`
- `reopen_issue(repo_name, issue_number)`
- `add_labels_to_issue(repo_name, issue_number, labels)`
- `assign_issue(repo_name, issue_number, assignees)`

#### Branch Methods

- `create_branch(repo_name, branch_name, source_branch="main", sha=None)`
- `get_branch(repo_name, branch_name)`
- `list_branches(repo_name, protected=None)`
- `delete_branch(repo_name, branch_name)`
- `compare_branches(repo_name, base, head)`
- `merge_branch(repo_name, base, head, commit_message=None)`
- `rename_branch(repo_name, old_name, new_name)`
- `get_branch_commits(repo_name, branch_name, since=None, until=None)`
- `get_branch_protection(repo_name, branch_name)`
- `set_branch_protection(repo_name, branch_name, **kwargs)`
- `remove_branch_protection(repo_name, branch_name)`

## Error Handling

The module includes comprehensive error handling with logging. All methods will raise `GithubException` for GitHub API errors and `ValueError` for invalid parameters.

```python
try:
    pr = gh.create_pull_request("owner/repo", "Title", "Body", "head", "main")
except GithubException as e:
    print(f"GitHub API error: {e}")
except ValueError as e:
    print(f"Invalid parameter: {e}")
```

## Running the Example

1. Set your GitHub token:
```bash
export GITHUB_TOKEN=your_token_here
```

2. Update the repository name in `example_usage.py`

3. Run the example:
```bash
python example_usage.py
```

4. Run branch-specific examples:
```bash
python -c "from example_usage import branch_examples; branch_examples()"
```

## Requirements

- Python 3.7+
- PyGithub 1.59.0+
- GitHub personal access token with appropriate permissions

## GitHub Token Permissions

Your GitHub token needs the following permissions:
- `repo` (Full control of private repositories)
- `public_repo` (Access public repositories)
- `issues` (Read and write access to issues)
- `pull_requests` (Read and write access to pull requests)

## License

This project is open source and available under the MIT License.