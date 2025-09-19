#!/usr/bin/env python3
"""
Test Script: Enhanced Package-Specific Vulnerability Search

This script demonstrates the Scout Agent's enhanced search capabilities
using specific package names rather than generic CVE searches.
"""

import logging
from scout_agent.scout_agent import ScoutAgent

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_package_specific_search():
    """Test package-specific vulnerability searches"""
    
    print("🚀 Testing Enhanced Package-Specific Vulnerability Search")
    print("=" * 60)
    
    # Initialize Scout Agent
    scout = ScoutAgent()
    
    # Test popular packages that are likely to have vulnerabilities
    test_packages = ["express", "lodash", "webpack", "react", "axios"]
    
    print("--- Test 1: General Search (Original Behavior) ---")
    print("Searching with hardcoded 'CVE-2024' query...")
    general_vulns = scout.scrape_real_vulnerabilities_via_mcp(limit=5)
    print(f"✅ Found {len(general_vulns)} vulnerabilities:")
    for i, vuln in enumerate(general_vulns[:3], 1):
        print(f"  {i}. {vuln.cve_id} - {vuln.description[:80]}...")
    
    print()
    
    print("--- Test 2: Package-Specific Search (Enhanced Behavior) ---")
    print(f"Searching for vulnerabilities in packages: {test_packages}")
    package_vulns = scout.scrape_real_vulnerabilities_via_mcp(
        limit=8, 
        packages=test_packages
    )
    print(f"✅ Found {len(package_vulns)} vulnerabilities:")
    for i, vuln in enumerate(package_vulns[:5], 1):
        print(f"  {i}. {vuln.cve_id} - {vuln.description[:80]}...")
        # Check if any of our test packages are mentioned
        for package in test_packages:
            if package.lower() in vuln.description.lower():
                print(f"     🎯 Mentions package: {package}")
                break
    
    print()
    
    print("--- Test 3: Single Package Deep Search ---")
    high_risk_package = ["express"]  # Express.js often has security advisories
    express_vulns = scout.scrape_real_vulnerabilities_via_mcp(
        limit=5,
        packages=high_risk_package
    )
    print(f"Searching specifically for: {high_risk_package[0]}")
    print(f"✅ Found {len(express_vulns)} vulnerabilities:")
    for i, vuln in enumerate(express_vulns[:3], 1):
        print(f"  {i}. {vuln.cve_id}")
        print(f"     Description: {vuln.description[:100]}...")
        print(f"     Severity: {vuln.severity}")
        print(f"     CVSS: {vuln.cvss_score}")
    
    print()
    
    print("--- Analysis ---")
    print(f"General search results: {len(general_vulns)}")
    print(f"Package-specific search results: {len(package_vulns)}")
    print(f"Single package search results: {len(express_vulns)}")
    
    # Check for uniqueness
    general_cves = {v.cve_id for v in general_vulns}
    package_cves = {v.cve_id for v in package_vulns}
    express_cves = {v.cve_id for v in express_vulns}
    
    print(f"Unique CVEs in general search: {len(general_cves)}")
    print(f"Unique CVEs in package search: {len(package_cves)}")
    print(f"Unique CVEs in express search: {len(express_cves)}")
    
    overlap = general_cves.intersection(package_cves)
    print(f"Overlap between general and package search: {len(overlap)} CVEs")
    
    if len(overlap) < len(package_cves):
        print("✅ Package-specific search is finding different results!")
        new_cves = package_cves - general_cves
        print(f"   New CVEs found: {list(new_cves)[:3]}")
    else:
        print("⚠️  Package search returning same results as general search")
    
    print()
    print("🎯 Enhanced search test completed!")

if __name__ == "__main__":
    test_package_specific_search()
