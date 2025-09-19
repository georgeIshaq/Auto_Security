#!/usr/bin/env python3
"""
Example usage of GitHub Integration functions.

This script demonstrates how to use the GitHub integration module
to create pull requests, manage issues, and interact with GitHub API.

Before running this script:
1. Install dependencies: pip install -r requirements.txt
2. Set your GitHub token: export GITHUB_TOKEN=your_token_here
3. Update the repo_name variable with your repository
"""

import os
from github_integration import create_github_integration


def main():
    """Main example function demonstrating GitHub integration features."""
    
    # Check if GitHub token is set
    if not os.getenv('GITHUB_TOKEN'):
        print("Error: Please set GITHUB_TOKEN environment variable")
        print("Example: export GITHUB_TOKEN=your_github_token_here")
        return
    
    try:
        # Initialize GitHub integration
        gh = create_github_integration()
        print(f"✅ Connected to GitHub as: {gh.user.login}")
        
        # Update this with your repository
        repo_name = "georgeIshaq/Auto_Security"
        print(f"📁 Working with repository: {repo_name}")

        """
        
        # Example 1: Create a pull request
        print("\n🔀 Creating a pull request...")
        pr = gh.create_pull_request(
            repo_name=repo_name,
            title="Example PR: Add new feature",
            body="This is an example pull request created by the GitHub integration script.\n\n## Changes\n- Added new functionality\n- Updated documentation\n\n## Testing\n- [ ] Unit tests pass\n- [ ] Integration tests pass",
            head="feature-branch",  # Make sure this branch exists
            base="main",
            draft=False
        )
        print(f"✅ Created PR #{pr.number}: {pr.title}")
        
        # Example 2: Comment on the pull request
        print("\n💬 Adding comment to pull request...")
        gh.comment_on_pull_request(
            repo_name=repo_name,
            pr_number=pr.number,
            comment="This is an automated comment from the GitHub integration script. Great work! 🚀"
        )
        print("✅ Added comment to PR")

        """
        
        # Example 3: Create an issue
        print("\n🐛 Creating an issue...")
        issue = gh.create_issue(
            repo_name=repo_name,
            title="Example Issue: Bug report",
            body="This is an example issue created by the GitHub integration script.\n\n## Description\nThis is a sample bug report to demonstrate the issue creation functionality.\n\n## Steps to Reproduce\n1. Do something\n2. Observe the issue\n\n## Expected Behavior\nWhat should happen\n\n## Actual Behavior\nWhat actually happens",
            labels=["bug", "example", "documentation"],
            assignees=[]  # Add usernames here if you want to assign
        )
        print(f"✅ Created issue #{issue.number}: {issue.title}")
        
        # Example 4: Comment on the issue
        print("\n💬 Adding comment to issue...")
        gh.comment_on_issue(
            repo_name=repo_name,
            issue_number=issue.number,
            comment="Thanks for reporting this issue! I'll investigate and get back to you. 🔍"
        )
        print("✅ Added comment to issue")
        
        # Example 5: List open issues
        print("\n📋 Listing open issues...")
        issues = gh.list_issues(repo_name=repo_name, state="open")
        print(f"Found {len(issues)} open issues:")
        for issue in issues[:5]:  # Show first 5 issues
            print(f"  - #{issue.number}: {issue.title}")
        
        # Example 6: List open pull requests
        print("\n📋 Listing open pull requests...")
        prs = gh.list_pull_requests(repo_name=repo_name, state="open")
        print(f"Found {len(prs)} open pull requests:")
        for pr in prs[:5]:  # Show first 5 PRs
            print(f"  - #{pr.number}: {pr.title}")
        
        # Example 7: Add labels to issue
        print("\n🏷️ Adding labels to issue...")
        gh.add_labels_to_issue(
            repo_name=repo_name,
            issue_number=issue.number,
            labels=["priority-high", "needs-review"]
        )
        print("✅ Added labels to issue")
        
        # Example 8: Branch operations
        print("\n🌿 Branch operations...")
        
        # Create a new branch
        new_branch = gh.create_branch(
            repo_name=repo_name,
            branch_name="feature/example-branch",
            source_branch="main"
        )
        print(f"✅ Created branch: {new_branch.name}")
        
        # List all branches
        branches = gh.list_branches(repo_name=repo_name)
        print(f"📋 Found {len(branches)} branches:")
        for branch in branches[:5]:  # Show first 5 branches
            print(f"  - {branch.name} (protected: {branch.protected})")
        
        # Compare branches
        comparison = gh.compare_branches(repo_name, "main", new_branch.name)
        print(f"📊 Branch comparison: {comparison.ahead_by} commits ahead, {comparison.behind_by} commits behind")
        
        # Get branch commits
        commits = gh.get_branch_commits(repo_name, new_branch.name)
        print(f"📝 Found {len(commits)} commits in branch '{new_branch.name}'")
        
        # Clean up: delete the example branch
        gh.delete_branch(repo_name, new_branch.name)
        print(f"🗑️ Deleted example branch: {new_branch.name}")
        
        print("\n🎉 All examples completed successfully!")
        print(f"📝 Created PR: {pr.html_url}")
        print(f"🐛 Created Issue: {issue.html_url}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\nTroubleshooting:")
        print("1. Make sure GITHUB_TOKEN is set correctly")
        print("2. Verify the repository name is correct")
        print("3. Check that you have the necessary permissions")
        print("4. Ensure the source branch exists for PR creation")


def branch_examples():
    """Dedicated function demonstrating branch operations."""
    
    if not os.getenv('GITHUB_TOKEN'):
        print("Error: Please set GITHUB_TOKEN environment variable")
        return
    
    try:
        gh = create_github_integration()
        repo_name = "georgeIshaq/Auto_Security"
        
        print("🌿 Branch Management Examples")
        print("=" * 40)
        
        # Create a feature branch
        print("\n1. Creating a feature branch...")
        feature_branch = gh.create_branch(
            repo_name=repo_name,
            branch_name="feature/new-feature",
            source_branch="main"
        )
        print(f"✅ Created branch: {feature_branch.name}")
        
        # Create a hotfix branch
        print("\n2. Creating a hotfix branch...")
        hotfix_branch = gh.create_branch(
            repo_name=repo_name,
            branch_name="hotfix/critical-fix",
            source_branch="main"
        )
        print(f"✅ Created branch: {hotfix_branch.name}")
        
        # List all branches
        print("\n3. Listing all branches...")
        all_branches = gh.list_branches(repo_name=repo_name)
        print(f"📋 Found {len(all_branches)} branches:")
        for branch in all_branches:
            print(f"  - {branch.name} (protected: {branch.protected})")
        
        # List only protected branches
        print("\n4. Listing protected branches...")
        protected_branches = gh.list_branches(repo_name=repo_name, protected=True)
        print(f"🛡️ Found {len(protected_branches)} protected branches:")
        for branch in protected_branches:
            print(f"  - {branch.name}")
        
        # Compare branches
        print("\n5. Comparing branches...")
        comparison = gh.compare_branches(repo_name, "main", feature_branch.name)
        print(f"📊 Comparison between 'main' and '{feature_branch.name}':")
        print(f"  - Ahead by: {comparison.ahead_by} commits")
        print(f"  - Behind by: {comparison.behind_by} commits")
        print(f"  - Total commits: {comparison.total_commits}")
        
        # Get commits from a branch
        print("\n6. Getting commits from feature branch...")
        commits = gh.get_branch_commits(repo_name, feature_branch.name)
        print(f"📝 Found {len(commits)} commits in '{feature_branch.name}':")
        for commit in commits[:3]:  # Show first 3 commits
            print(f"  - {commit.sha[:7]}: {commit.commit.message.split(chr(10))[0]}")
        
        # Set branch protection (example for main branch)
        print("\n7. Setting branch protection...")
        try:
            gh.set_branch_protection(
                repo_name=repo_name,
                branch_name="main",
                required_status_checks={"strict": True, "contexts": ["ci/tests"]},
                enforce_admins=True,
                required_pull_request_reviews={"required_approving_review_count": 2},
                allow_force_pushes=False,
                allow_deletions=False
            )
            print("✅ Set protection rules for 'main' branch")
        except Exception as e:
            print(f"⚠️ Could not set protection (may not have admin rights): {e}")
        
        # Get branch protection info
        print("\n8. Getting branch protection info...")
        try:
            protection = gh.get_branch_protection(repo_name, "main")
            print("🛡️ Protection rules for 'main' branch:")
            print(f"  - Enforce admins: {protection.get('enforce_admins', False)}")
            print(f"  - Allow force pushes: {protection.get('allow_force_pushes', False)}")
            print(f"  - Allow deletions: {protection.get('allow_deletions', False)}")
        except Exception as e:
            print(f"⚠️ Could not get protection info: {e}")
        
        # Rename a branch
        print("\n9. Renaming branch...")
        renamed_branch = gh.rename_branch(
            repo_name=repo_name,
            old_name="hotfix/critical-fix",
            new_name="hotfix/urgent-fix"
        )
        print(f"✅ Renamed branch to: {renamed_branch.name}")
        
        # Clean up: delete example branches
        print("\n10. Cleaning up example branches...")
        gh.delete_branch(repo_name, feature_branch.name)
        gh.delete_branch(repo_name, renamed_branch.name)
        print("🗑️ Deleted example branches")
        
        print("\n🎉 Branch examples completed successfully!")
        
    except Exception as e:
        print(f"❌ Error: {e}")


def cleanup_example():
    """Cleanup function to close the created PR and issue (optional)."""
    
    if not os.getenv('GITHUB_TOKEN'):
        print("Error: Please set GITHUB_TOKEN environment variable")
        return
    
    try:
        gh = create_github_integration()
        repo_name = "georgeIshaq/Auto_Security"
        
        print("🧹 Cleaning up example PR and issue...")
        
        # Close the example PR (uncomment if you want to close it)
        # gh.close_pull_request(repo_name, pr_number)
        
        # Close the example issue (uncomment if you want to close it)
        # gh.close_issue(repo_name, issue_number)
        
        print("✅ Cleanup completed")
        
    except Exception as e:
        print(f"❌ Cleanup error: {e}")


if __name__ == "__main__":
    print("🚀 GitHub Integration Example")
    print("=" * 40)
    
    # Run the main example
    main()
    
    # Uncomment the lines below to run additional examples
    # branch_examples()  # Run branch management examples
    # cleanup_example()  # Run cleanup
