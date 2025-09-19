#!/usr/bin/env python3
"""
Test script for the vulnerability scanner

This script demonstrates the vulnerability scanning capabilities
and tests the integration with the Scout Agent.
"""

import os
import sys
import json
from pathlib import Path

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from vulnerability_scanner import VulnerabilityScanner
from demo_scanner import DemoRepositoryScanner
from scout_agent import ScoutAgent

def test_basic_scanner():
    """Test basic vulnerability scanner functionality"""
    print("=" * 60)
    print("TESTING BASIC VULNERABILITY SCANNER")
    print("=" * 60)
    
    # Create a test file with vulnerabilities
    test_code = """
// Test file with intentional vulnerabilities
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

// XSS vulnerability
app.get('/profile/:username', (req, res) => {
  const username = req.params.username;
  res.send(`<h1>Welcome ${username}</h1>`);
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

// Weak password comparison
app.post('/login', (req, res) => {
  if (req.body.password == 'admin123') {
    res.json({success: true});
  }
});
"""
    
    # Write test file
    test_file = "test_vulnerable_code.js"
    with open(test_file, 'w') as f:
        f.write(test_code)
    
    try:
        # Initialize scanner
        scanner = VulnerabilityScanner()
        
        # Scan the test file
        print("Scanning test file...")
        findings = scanner.detect_vulnerabilities_in_file(test_file, test_code)
        
        print(f"Found {len(findings)} vulnerabilities:")
        for i, finding in enumerate(findings, 1):
            print(f"  {i}. {finding.vulnerability_type} - {finding.severity}")
            print(f"     File: {finding.file_path}:{finding.line_number}")
            print(f"     Evidence: {finding.evidence}")
            print()
        
        return len(findings) > 0
        
    finally:
        # Clean up test file
        if os.path.exists(test_file):
            os.remove(test_file)

def test_demo_scanner():
    """Test demo repository scanner"""
    print("=" * 60)
    print("TESTING DEMO REPOSITORY SCANNER")
    print("=" * 60)
    
    demo_path = "/Users/iamwafula/GitHub/upload-worker/Auto_Security/repo_demo"
    
    if not os.path.exists(demo_path):
        print(f"Demo repository not found at {demo_path}")
        return False
    
    try:
        # Initialize demo scanner
        scanner = DemoRepositoryScanner()
        
        # Scan demo repository
        print("Scanning demo repository...")
        scan_result = scanner.scan_demo_repository(demo_path)
        
        print(f"Scan completed:")
        print(f"  Total findings: {scan_result.total_findings}")
        print(f"  Scan duration: {scan_result.scan_duration:.2f} seconds")
        
        if scan_result.findings_by_severity:
            print("  Findings by severity:")
            for severity, count in scan_result.findings_by_severity.items():
                print(f"    {severity}: {count}")
        
        # Show some findings
        if scan_result.findings:
            print("\n  Sample findings:")
            for i, finding in enumerate(scan_result.findings[:3], 1):
                print(f"    {i}. {finding.severity} - {finding.vulnerability_type}")
                print(f"       File: {finding.file_path}:{finding.line_number}")
                print(f"       Description: {finding.description}")
        
        return scan_result.total_findings > 0
        
    except Exception as e:
        print(f"Error scanning demo repository: {e}")
        return False

def test_scout_agent():
    """Test Scout Agent functionality"""
    print("=" * 60)
    print("TESTING SCOUT AGENT")
    print("=" * 60)
    
    try:
        # Initialize Scout Agent
        scout = ScoutAgent()
        
        # Populate knowledge base
        print("Populating knowledge base...")
        results = scout.populate_knowledge_base(vuln_limit=3, patch_limit=2)
        print(f"Knowledge base populated: {results}")
        
        # Test vulnerability search
        print("\nTesting vulnerability search...")
        vuln_results = scout.find_similar_vulnerabilities("SQL injection in web application", k=2)
        print(f"Found {len(vuln_results)} similar vulnerabilities")
        
        for i, result in enumerate(vuln_results, 1):
            cve_id = result['metadata'].get('cve_id', 'Unknown')
            severity = result['metadata'].get('severity', 'Unknown')
            print(f"  {i}. {cve_id} - {severity}")
        
        # Test patch search
        print("\nTesting patch search...")
        patch_results = scout.find_proven_patches("sql_injection", language="javascript", k=2)
        print(f"Found {len(patch_results)} proven patches")
        
        for i, result in enumerate(patch_results, 1):
            patch_id = result['metadata'].get('patch_id', 'Unknown')
            effectiveness = result['metadata'].get('effectiveness_score', 'Unknown')
            print(f"  {i}. {patch_id} - Effectiveness: {effectiveness}")
        
        return True
        
    except Exception as e:
        print(f"Error testing Scout Agent: {e}")
        return False

def test_integration():
    """Test integration between scanner and Scout Agent"""
    print("=" * 60)
    print("TESTING SCANNER-SCOUT INTEGRATION")
    print("=" * 60)
    
    try:
        # Initialize both components
        scout = ScoutAgent()
        scanner = VulnerabilityScanner(scout)
        
        # Populate knowledge base
        print("Populating knowledge base...")
        scout.populate_knowledge_base(vuln_limit=3, patch_limit=2)
        
        # Create test code with SQL injection
        test_code = """
app.get('/users/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  db.query(query, (err, results) => {
    res.json(results);
  });
});
"""
        
        # Scan with AI context
        print("Scanning with AI context...")
        findings = scanner.detect_vulnerabilities_in_file("test.js", test_code)
        
        if findings:
            finding = findings[0]
            print(f"Found vulnerability: {finding.vulnerability_type}")
            print(f"Severity: {finding.severity}")
            print(f"Confidence: {finding.confidence}")
            
            if finding.cve_matches:
                print(f"Related CVEs: {len(finding.cve_matches)}")
                for cve in finding.cve_matches[:1]:
                    cve_id = cve['metadata'].get('cve_id', 'Unknown')
                    print(f"  - {cve_id}")
            
            if finding.suggested_patches:
                print(f"Suggested patches: {len(finding.suggested_patches)}")
                for patch in finding.suggested_patches[:1]:
                    patch_id = patch['metadata'].get('patch_id', 'Unknown')
                    print(f"  - {patch_id}")
        
        return len(findings) > 0
        
    except Exception as e:
        print(f"Error testing integration: {e}")
        return False

def main():
    """Run all tests"""
    print("VULNERABILITY SCANNER TEST SUITE")
    print("=" * 80)
    
    tests = [
        ("Basic Scanner", test_basic_scanner),
        ("Demo Scanner", test_demo_scanner),
        ("Scout Agent", test_scout_agent),
        ("Integration", test_integration)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"\nRunning {test_name} test...")
        try:
            result = test_func()
            results[test_name] = result
            status = "PASS" if result else "FAIL"
            print(f"{test_name}: {status}")
        except Exception as e:
            print(f"{test_name}: ERROR - {e}")
            results[test_name] = False
    
    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        status = "PASS" if result else "FAIL"
        print(f"{test_name:20}: {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ All tests passed!")
        return 0
    else:
        print("❌ Some tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
