#!/usr/bin/env python3
"""
Example usage of the vulnerability scanner with the specific vulnerability format

This script demonstrates how to use the vulnerability scanner to detect
vulnerabilities stored in the format you specified.
"""

import json
from scout_agent import ScoutAgent, VulnerabilityData
from vulnerability_scanner import VulnerabilityScanner
from demo_scanner import DemoRepositoryScanner

def create_sample_vulnerability():
    """Create a sample vulnerability in your specified format"""
    return VulnerabilityData(
        cve_id="CVE-2023-42363",
        description="BusyBox before 1.35.0 allows remote attackers to execute arbitrary code if netstat is used",
        severity="CRITICAL",
        cvss_score=9.8,
        affected_packages=["busybox"],
        vulnerability_type="remote_code_execution",
        published_date="2023-11-28",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-42363"],
        exploit_available=True,
        patch_available=True
    )

def example_basic_scan():
    """Example of basic vulnerability scanning"""
    print("=" * 60)
    print("EXAMPLE: Basic Vulnerability Scanning")
    print("=" * 60)
    
    # Create sample vulnerable code
    vulnerable_code = """
// Vulnerable Express.js application
const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');

const app = express();

// SQL Injection vulnerability
app.get('/users/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// Command injection vulnerability  
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    res.json({output: stdout, error: stderr});
  });
});

// Hardcoded secret
const JWT_SECRET = 'my-super-secret-key-12345';
"""
    
    # Initialize scanner
    scanner = VulnerabilityScanner()
    
    # Scan the code
    findings = scanner.detect_vulnerabilities_in_file("example.js", vulnerable_code)
    
    print(f"Found {len(findings)} vulnerabilities:")
    for i, finding in enumerate(findings, 1):
        print(f"\n{i}. {finding.vulnerability_type.upper()} - {finding.severity}")
        print(f"   File: {finding.file_path}:{finding.line_number}")
        print(f"   Confidence: {finding.confidence:.2f}")
        print(f"   Description: {finding.description}")
        print(f"   Evidence: {finding.evidence}")
        print(f"   Code snippet:")
        for line in finding.code_snippet.split('\n')[:3]:
            print(f"     {line}")

def example_with_ai_context():
    """Example of scanning with AI-powered context"""
    print("\n" + "=" * 60)
    print("EXAMPLE: Scanning with AI Context")
    print("=" * 60)
    
    # Initialize Scout Agent and populate with your vulnerability format
    scout = ScoutAgent()
    
    # Add your specific vulnerability
    vuln = create_sample_vulnerability()
    scout.ingest_vulnerability(vuln)
    
    # Add some additional vulnerabilities for context
    additional_vulns = [
        VulnerabilityData(
            cve_id="CVE-2023-12345",
            description="SQL injection vulnerability in web applications",
            severity="HIGH",
            cvss_score=8.5,
            affected_packages=["express", "mysql"],
            vulnerability_type="sql_injection",
            published_date="2023-12-01",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            references=["https://example.com/cve-2023-12345"],
            exploit_available=True,
            patch_available=True
        ),
        VulnerabilityData(
            cve_id="CVE-2023-12346",
            description="Command injection via child_process.exec",
            severity="CRITICAL",
            cvss_score=9.1,
            affected_packages=["node"],
            vulnerability_type="command_injection",
            published_date="2023-12-02",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            references=["https://example.com/cve-2023-12346"],
            exploit_available=True,
            patch_available=True
        )
    ]
    
    for vuln in additional_vulns:
        scout.ingest_vulnerability(vuln)
    
    # Initialize scanner with AI context
    scanner = VulnerabilityScanner(scout)
    
    # Create vulnerable code
    vulnerable_code = """
app.get('/users/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    res.json({output: stdout, error: stderr});
  });
});
"""
    
    # Scan with AI context
    findings = scanner.detect_vulnerabilities_in_file("example.js", vulnerable_code)
    
    print(f"Found {len(findings)} vulnerabilities with AI context:")
    for i, finding in enumerate(findings, 1):
        print(f"\n{i}. {finding.vulnerability_type.upper()} - {finding.severity}")
        print(f"   File: {finding.file_path}:{finding.line_number}")
        print(f"   Confidence: {finding.confidence:.2f}")
        print(f"   Description: {finding.description}")
        
        # Show AI context
        if finding.cve_matches:
            print(f"   Related CVEs: {len(finding.cve_matches)}")
            for cve in finding.cve_matches[:2]:
                cve_id = cve['metadata'].get('cve_id', 'Unknown')
                severity = cve['metadata'].get('severity', 'Unknown')
                print(f"     - {cve_id} ({severity})")
        
        if finding.suggested_patches:
            print(f"   Suggested Patches: {len(finding.suggested_patches)}")
            for patch in finding.suggested_patches[:1]:
                patch_id = patch['metadata'].get('patch_id', 'Unknown')
                effectiveness = patch['metadata'].get('effectiveness_score', 'Unknown')
                print(f"     - {patch_id} (Effectiveness: {effectiveness})")

def example_demo_scan():
    """Example of scanning the demo repository"""
    print("\n" + "=" * 60)
    print("EXAMPLE: Demo Repository Scan")
    print("=" * 60)
    
    # Initialize demo scanner
    scanner = DemoRepositoryScanner()
    
    # Scan demo repository
    demo_path = "/Users/iamwafula/GitHub/upload-worker/Auto_Security/repo_demo"
    scan_result = scanner.scan_demo_repository(demo_path)
    
    print(f"Demo scan completed:")
    print(f"  Total findings: {scan_result.total_findings}")
    print(f"  Scan duration: {scan_result.scan_duration:.2f} seconds")
    
    if scan_result.findings_by_severity:
        print("  Findings by severity:")
        for severity, count in scan_result.findings_by_severity.items():
            print(f"    {severity}: {count}")
    
    # Show top findings
    if scan_result.findings:
        print("\n  Top findings:")
        for i, finding in enumerate(scan_result.findings[:3], 1):
            print(f"    {i}. {finding.severity} - {finding.vulnerability_type}")
            print(f"       File: {finding.file_path}:{finding.line_number}")
            print(f"       Description: {finding.description}")

def example_custom_vulnerability_format():
    """Example of working with your specific vulnerability format"""
    print("\n" + "=" * 60)
    print("EXAMPLE: Custom Vulnerability Format")
    print("=" * 60)
    
    # Your vulnerability format
    vulnerability_data = {
        "cve_id": "CVE-2023-42363",
        "description": "BusyBox before 1.35.0 allows remote attackers to execute arbitrary code if netstat is used",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected_packages": ["busybox"],
        "vulnerability_type": "remote_code_execution",
        "published_date": "2023-11-28",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-42363"],
        "exploit_available": True,
        "patch_available": True
    }
    
    # Convert to VulnerabilityData object
    vuln = VulnerabilityData(**vulnerability_data)
    
    # Initialize Scout Agent and add vulnerability
    scout = ScoutAgent()
    scout.ingest_vulnerability(vuln)
    
    print(f"Added vulnerability: {vuln.cve_id}")
    print(f"  Description: {vuln.description}")
    print(f"  Severity: {vuln.severity} (CVSS: {vuln.cvss_score})")
    print(f"  Affected packages: {', '.join(vuln.affected_packages)}")
    print(f"  Exploit available: {vuln.exploit_available}")
    print(f"  Patch available: {vuln.patch_available}")
    
    # Search for similar vulnerabilities
    print("\nSearching for similar vulnerabilities...")
    similar = scout.find_similar_vulnerabilities("remote code execution", k=3)
    print(f"Found {len(similar)} similar vulnerabilities")
    
    for i, result in enumerate(similar, 1):
        cve_id = result['metadata'].get('cve_id', 'Unknown')
        severity = result['metadata'].get('severity', 'Unknown')
        print(f"  {i}. {cve_id} - {severity}")

def main():
    """Run all examples"""
    print("VULNERABILITY SCANNER EXAMPLES")
    print("=" * 80)
    
    try:
        # Run examples
        example_basic_scan()
        example_with_ai_context()
        example_demo_scan()
        example_custom_vulnerability_format()
        
        print("\n" + "=" * 80)
        print("All examples completed successfully!")
        print("=" * 80)
        
    except Exception as e:
        print(f"Error running examples: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
