#!/usr/bin/env python3
"""
Fast Test: Single Package Vulnerability Scan

Quick test to verify the enhanced search is working with just one package.
"""

import logging
from scout_agent.scout_agent import ScoutAgent

# Minimal logging
logging.basicConfig(level=logging.ERROR)

def quick_test():
    """Quick test with just one high-risk package"""
    
    print("🚀 Quick Package Vulnerability Test")
    print("=" * 40)
    
    # Initialize Scout Agent
    scout = ScoutAgent()
    
    # Test 1: Old behavior (general search)
    print("1. General search (old behavior)...")
    general_vulns = scout.scrape_real_vulnerabilities_via_mcp(limit=3)
    print(f"   Found: {len(general_vulns)} vulnerabilities")
    if general_vulns:
        print(f"   Example: {general_vulns[0].cve_id}")
    
    print()
    
    # Test 2: New behavior (package-specific search)
    print("2. Package-specific search (new behavior)...")
    print("   Searching for: express (popular Node.js framework)")
    
    package_vulns = scout.scrape_real_vulnerabilities_via_mcp(
        limit=3,
        packages=["express"]  # Just one package
    )
    
    print(f"   Found: {len(package_vulns)} vulnerabilities")
    if package_vulns:
        print(f"   Example: {package_vulns[0].cve_id}")
        # Check if "express" is mentioned
        for vuln in package_vulns:
            if "express" in vuln.description.lower():
                print(f"   ✅ Found express-specific vulnerability: {vuln.cve_id}")
                break
    
    print()
    
    # Compare results
    general_cves = {v.cve_id for v in general_vulns}
    package_cves = {v.cve_id for v in package_vulns}
    
    if general_cves != package_cves:
        print("✅ SUCCESS: Package search found different results!")
        print(f"   General CVEs: {list(general_cves)}")
        print(f"   Express CVEs: {list(package_cves)}")
    else:
        print("⚠️  Package search returned same results as general search")
    
    print()
    print("🎯 Quick test complete!")

if __name__ == "__main__":
    quick_test()
