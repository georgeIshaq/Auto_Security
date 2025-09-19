#!/usr/bin/env python3
"""
Simple Demo: Repository-Aware Vulnerability Scanning

This shows how to scan a GitHub repository for vulnerabilities
based on its actual dependencies.
"""

import os
import logging
from scout_agent.scout_agent import ScoutAgent

# Set up basic logging
logging.basicConfig(level=logging.WARNING)  # Reduce noise

def scan_repo_for_vulns(repo_name, github_token=None):
    """
    Scan a GitHub repository for vulnerabilities based on its dependencies
    
    Args:
        repo_name: GitHub repo in format 'owner/repo' (e.g., 'facebook/react')
        github_token: GitHub token (optional, can use GITHUB_TOKEN env var)
    """
    print(f"🔍 Scanning repository: {repo_name}")
    print("=" * 50)
    
    # Initialize Scout Agent
    scout = ScoutAgent()
    
    # This ONE method call does everything:
    # 1. Connects to GitHub
    # 2. Reads package.json, requirements.txt, etc.
    # 3. Extracts package names
    # 4. Searches for vulnerabilities specific to those packages
    vulnerabilities = scout.scan_repository_for_vulnerabilities(
        repo_name=repo_name,
        github_token=github_token
    )
    
    print(f"✅ Found {len(vulnerabilities)} vulnerabilities")
    
    # Show results
    for i, vuln in enumerate(vulnerabilities[:5], 1):
        print(f"\\n{i}. {vuln.cve_id}")
        print(f"   Severity: {vuln.severity}")
        print(f"   Description: {vuln.description[:100]}...")
        if vuln.affected_packages:
            print(f"   Affects: {', '.join(vuln.affected_packages[:3])}")
    
    return vulnerabilities

if __name__ == "__main__":
    # You need to set GITHUB_TOKEN environment variable
    # or pass it directly to the function
    
    # Example repositories to test:
    test_repos = [
        "expressjs/express",    # Node.js web framework
        "facebook/react",       # React library
        "django/django",        # Python web framework
    ]
    
    print("🚀 Repository Vulnerability Scanner")
    print("Make sure GITHUB_TOKEN environment variable is set!")
    print()
    
    # Test with first repo
    repo = test_repos[0]
    try:
        vulns = scan_repo_for_vulns(repo)
        print(f"\\n🎯 Scan complete! Found vulnerabilities for {repo}")
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\\nTo fix:")
        print("1. Set GITHUB_TOKEN environment variable")
        print("2. Or pass github_token parameter to function")
