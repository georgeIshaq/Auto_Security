#!/usr/bin/env python3
"""
Manual Package Vulnerability Scanning

Scan for vulnerabilities in specific packages without needing GitHub access.
"""

import logging
from scout_agent.scout_agent import ScoutAgent

# Reduce logging noise
logging.basicConfig(level=logging.WARNING)

def scan_packages_for_vulns(packages):
    """
    Scan specific packages for vulnerabilities
    
    Args:
        packages: List of package names to scan
    """
    print(f"🔍 Scanning packages: {', '.join(packages)}")
    print("=" * 50)
    
    # Initialize Scout Agent
    scout = ScoutAgent()
    
    # Search for vulnerabilities specific to these packages
    vulnerabilities = scout.scrape_real_vulnerabilities_via_mcp(
        limit=10,
        packages=packages  # This is the key enhancement!
    )
    
    print(f"✅ Found {len(vulnerabilities)} vulnerabilities")
    
    # Show results
    for i, vuln in enumerate(vulnerabilities[:5], 1):
        print(f"\\n{i}. {vuln.cve_id}")
        print(f"   Severity: {vuln.severity}")
        print(f"   Description: {vuln.description[:100]}...")
        
        # Check which packages are mentioned
        mentioned_packages = []
        for pkg in packages:
            if pkg.lower() in vuln.description.lower():
                mentioned_packages.append(pkg)
        
        if mentioned_packages:
            print(f"   🎯 Mentions: {', '.join(mentioned_packages)}")
    
    return vulnerabilities

if __name__ == "__main__":
    print("🚀 Manual Package Vulnerability Scanner")
    print()
    
    # Example package lists (limited to 5 max for speed)
    
    print("--- High-Risk JavaScript Packages ---")
    js_packages = ["express", "lodash", "axios"]  # Only 3 packages for speed
    js_vulns = scan_packages_for_vulns(js_packages)
    
    print("\\n--- High-Risk Python Packages ---")
    python_packages = ["django", "requests"]  # Only 2 packages for speed
    py_vulns = scan_packages_for_vulns(python_packages)
    
    print("\\n--- Summary ---")
    print(f"JavaScript packages: {len(js_vulns)} vulnerabilities")
    print(f"Python packages: {len(py_vulns)} vulnerabilities")
