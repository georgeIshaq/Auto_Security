#!/usr/bin/env python3
"""
Test Script: Repository-Aware Vulnerability Scanning

This script demonstrates the enhanced Scout Agent's ability to perform
targeted vulnerability scanning based on repository dependencies.
"""

import os
import logging
from scout_agent.scout_agent import ScoutAgent

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_repo_scan():
    """Test the repository-aware vulnerability scanning"""
    
    print("🚀 Testing Repository-Aware Vulnerability Scanning")
    print("=" * 60)
    
    # Test with a public repository (you can change this)
    test_repo = "facebook/react"  # A popular repo with known dependencies
    
    print(f"📁 Target Repository: {test_repo}")
    print()
    
    # Initialize Scout Agent
    scout = ScoutAgent()
    
    # Test 1: Extract packages from repository
    print("--- Step 1: Package Extraction ---")
    try:
        from github_client.github_integration import GitHubIntegration
        gh_client = GitHubIntegration()
        packages = gh_client.extract_packages_from_repo(test_repo)
        print(f"✅ Found {len(packages)} packages:")
        for i, package in enumerate(packages[:10], 1):  # Show first 10
            print(f"   {i}. {package}")
        if len(packages) > 10:
            print(f"   ... and {len(packages) - 10} more")
    except Exception as e:
        print(f"❌ Package extraction failed: {e}")
        return
    
    print()
    
    # Test 2: Repository-aware vulnerability scan
    print("--- Step 2: Repository-Aware Vulnerability Scan ---")
    try:
        vulnerabilities = scout.scan_repository_for_vulnerabilities(test_repo)
        print(f"✅ Found {len(vulnerabilities)} vulnerabilities:")
        
        for i, vuln in enumerate(vulnerabilities[:5], 1):  # Show first 5
            print(f"\\n{i}. CVE: {vuln.cve_id}")
            print(f"   Description: {vuln.description[:100]}...")
            print(f"   Severity: {vuln.severity}")
            print(f"   CVSS: {vuln.cvss_score}")
            print(f"   Packages: {', '.join(vuln.affected_packages[:3])}")
            
        if len(vulnerabilities) > 5:
            print(f"\\n   ... and {len(vulnerabilities) - 5} more vulnerabilities")
            
    except Exception as e:
        print(f"❌ Repository scan failed: {e}")
        return
    
    print()
    
    # Test 3: Compare with general scan
    print("--- Step 3: Comparison with General Scan ---")
    try:
        general_vulns = scout.scrape_real_vulnerabilities_via_mcp(limit=5)
        print(f"General scan found {len(general_vulns)} vulnerabilities")
        print(f"Repo-specific scan found {len(vulnerabilities)} vulnerabilities")
        
        # Check for package-specific results
        package_specific_count = 0
        for vuln in vulnerabilities:
            for package in packages[:5]:  # Check against top packages
                if package.lower() in vuln.description.lower():
                    package_specific_count += 1
                    break
        
        print(f"Package-specific vulnerabilities: {package_specific_count}/{len(vulnerabilities)}")
        
    except Exception as e:
        print(f"❌ Comparison failed: {e}")
    
    print()
    print("🎯 Test completed!")

if __name__ == "__main__":
    test_repo_scan()
