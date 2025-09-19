"""
Demo Repository Scanner - Specialized scanner for the vulnerable demo app

This scanner is specifically designed to find vulnerabilities in the demo repository
and demonstrate the vulnerability scanning capabilities.
"""

import os
import json
import re
import logging
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path

from vulnerability_scanner import VulnerabilityScanner, ScanResult
from scout_agent import ScoutAgent, VulnerabilityData, PatchData

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DemoRepositoryScanner(VulnerabilityScanner):
    """
    Specialized scanner for the demo repository with enhanced patterns
    """
    
    def __init__(self):
        """Initialize demo scanner with enhanced patterns"""
        super().__init__()
        
        # Add demo-specific patterns
        self._add_demo_patterns()
        
        # Demo-specific vulnerability data
        self._demo_vulnerabilities = self._create_demo_vulnerabilities()
        self._demo_patches = self._create_demo_patches()

    def _add_demo_patterns(self):
        """Add demo-specific vulnerability patterns"""
        # Enhanced patterns for the demo app
        demo_patterns = {
            'javascript': {
                'sql_injection': [
                    # More specific patterns for the demo app
                    r'db\.query\s*\(\s*["\'].*\+.*req\.',  # Direct string concatenation
                    r'connection\.query\s*\(\s*["\'].*\+.*req\.',  # MySQL connection
                    r'SELECT.*\+.*req\.params',  # Express params
                    r'INSERT.*\+.*req\.body',  # Express body
                    r'UPDATE.*\+.*req\.query',  # Express query
                    r'DELETE.*\+.*req\.params',  # Express params
                ],
                'xss': [
                    r'res\.send\s*\(.*req\.',  # Direct response with user input
                    r'res\.json\s*\(.*req\.',  # JSON response with user input
                    r'<%=.*req\.',  # EJS template injection
                    r'<%-.*req\.',  # EJS template injection
                ],
                'command_injection': [
                    r'child_process\.exec\s*\(.*req\.',  # exec with user input
                    r'child_process\.spawn\s*\(.*req\.',  # spawn with user input
                    r'child_process\.execFile\s*\(.*req\.',  # execFile with user input
                ],
                'path_traversal': [
                    r'fs\.readFile\s*\(.*req\.params',  # File read with params
                    r'fs\.createReadStream\s*\(.*req\.params',  # File stream with params
                    r'path\.join\s*\(.*req\.params',  # Path join with params
                    r'res\.sendFile\s*\(.*req\.params',  # Send file with params
                ],
                'hardcoded_secrets': [
                    r'jwt\.sign\s*\(.*["\'][^"\']{20,}["\']',  # JWT secret
                    r'bcrypt\.hash\s*\(.*["\'][^"\']{10,}["\']',  # Bcrypt salt
                    r'process\.env\.SECRET.*=.*["\'][^"\']{10,}["\']',  # Hardcoded env vars
                ],
                'insecure_deserialization': [
                    r'JSON\.parse\s*\(.*req\.',  # JSON parse with user input
                    r'eval\s*\(.*req\.',  # eval with user input
                    r'Function\s*\(.*req\.',  # Function constructor with user input
                ],
                'weak_authentication': [
                    r'if\s*\(\s*password\s*==\s*["\']',  # Weak password comparison
                    r'if\s*\(\s*req\.body\.password\s*==\s*["\']',  # Direct password comparison
                    r'if\s*\(\s*req\.query\.token\s*==\s*["\']',  # Direct token comparison
                ],
                'cors_misconfiguration': [
                    r'cors\s*\(\s*\{\s*origin\s*:\s*true\s*\}',  # Wildcard CORS
                    r'cors\s*\(\s*\{\s*origin\s*:\s*["\']\*["\']\s*\}',  # Wildcard CORS
                ],
                'rate_limiting_bypass': [
                    r'rateLimit\s*\(\s*\{\s*skip\s*:\s*function',  # Skip function in rate limit
                    r'rateLimit\s*\(\s*\{\s*skipSuccessfulRequests\s*:\s*true',  # Skip successful requests
                ]
            }
        }
        
        # Merge with existing patterns
        for lang, patterns in demo_patterns.items():
            if lang in self.patterns:
                for vuln_type, pattern_list in patterns.items():
                    if vuln_type in self.patterns[lang]:
                        self.patterns[lang][vuln_type].extend(pattern_list)
                    else:
                        self.patterns[lang][vuln_type] = pattern_list
            else:
                self.patterns[lang] = patterns
        
        # Update severity and confidence mappings
        self.severity_map.update({
            'insecure_deserialization': 'CRITICAL',
            'weak_authentication': 'HIGH',
            'cors_misconfiguration': 'MEDIUM',
            'rate_limiting_bypass': 'MEDIUM'
        })
        
        self.confidence_map.update({
            'insecure_deserialization': 0.95,
            'weak_authentication': 0.85,
            'cors_misconfiguration': 0.8,
            'rate_limiting_bypass': 0.75
        })

    def _create_demo_vulnerabilities(self) -> List[VulnerabilityData]:
        """Create demo-specific vulnerability data"""
        return [
            VulnerabilityData(
                cve_id="CVE-2023-12345",
                description="Express.js SQL injection vulnerability in user authentication",
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
                description="Node.js command injection via child_process.exec",
                severity="CRITICAL",
                cvss_score=9.1,
                affected_packages=["node"],
                vulnerability_type="command_injection",
                published_date="2023-12-02",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                references=["https://example.com/cve-2023-12346"],
                exploit_available=True,
                patch_available=True
            ),
            VulnerabilityData(
                cve_id="CVE-2023-12347",
                description="Cross-site scripting (XSS) in Express.js response handling",
                severity="MEDIUM",
                cvss_score=6.1,
                affected_packages=["express"],
                vulnerability_type="xss",
                published_date="2023-12-03",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                references=["https://example.com/cve-2023-12347"],
                exploit_available=False,
                patch_available=True
            )
        ]

    def _create_demo_patches(self) -> List[PatchData]:
        """Create demo-specific patch data"""
        return [
            PatchData(
                patch_id="demo_sql_injection_fix_001",
                vulnerability_type="sql_injection",
                language="javascript",
                framework="express",
                patch_content="""
// Before (vulnerable)
app.get('/users/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({error: 'Database error'});
    res.json(results);
  });
});

// After (secure)
app.get('/users/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  if (isNaN(userId)) {
    return res.status(400).json({error: 'Invalid user ID'});
  }
  
  const query = 'SELECT * FROM users WHERE id = ?';
  db.query(query, [userId], (err, results) => {
    if (err) return res.status(500).json({error: 'Database error'});
    res.json(results);
  });
});
                """,
                description="Fix SQL injection by using parameterized queries and input validation",
                effectiveness_score=0.98,
                source_url="https://github.com/demo/security-fix-001",
                implementation_complexity="low",
                related_cves=["CVE-2023-12345"]
            ),
            PatchData(
                patch_id="demo_command_injection_fix_001",
                vulnerability_type="command_injection",
                language="javascript",
                framework="express",
                patch_content="""
// Before (vulnerable)
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    res.json({output: stdout, error: stderr});
  });
});

// After (secure)
app.get('/ping', (req, res) => {
  const host = req.query.host;
  
  // Validate host input
  if (!host || !/^[a-zA-Z0-9.-]+$/.test(host)) {
    return res.status(400).json({error: 'Invalid host format'});
  }
  
  // Use spawn instead of exec with shell
  const child = spawn('ping', ['-c', '1', host]);
  let output = '';
  let error = '';
  
  child.stdout.on('data', (data) => {
    output += data.toString();
  });
  
  child.stderr.on('data', (data) => {
    error += data.toString();
  });
  
  child.on('close', (code) => {
    res.json({output, error, exitCode: code});
  });
});
                """,
                description="Fix command injection by validating input and using spawn instead of exec",
                effectiveness_score=0.95,
                source_url="https://github.com/demo/security-fix-002",
                implementation_complexity="medium",
                related_cves=["CVE-2023-12346"]
            ),
            PatchData(
                patch_id="demo_xss_fix_001",
                vulnerability_type="xss",
                language="javascript",
                framework="express",
                patch_content="""
// Before (vulnerable)
app.get('/profile/:username', (req, res) => {
  const username = req.params.username;
  res.send(`<h1>Welcome ${username}</h1>`);
});

// After (secure)
const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

app.get('/profile/:username', (req, res) => {
  const username = escapeHtml(req.params.username);
  res.send(`<h1>Welcome ${username}</h1>`);
});

// Or better yet, use a template engine with auto-escaping
app.get('/profile/:username', (req, res) => {
  res.render('profile', {username: req.params.username});
});
                """,
                description="Fix XSS by escaping HTML characters or using template engines with auto-escaping",
                effectiveness_score=0.92,
                source_url="https://github.com/demo/security-fix-003",
                implementation_complexity="low",
                related_cves=["CVE-2023-12347"]
            )
        ]

    def populate_demo_knowledge_base(self):
        """Populate knowledge base with demo-specific data"""
        logger.info("Populating demo knowledge base...")
        
        # Ingest demo vulnerabilities
        vuln_success = 0
        for vuln in self._demo_vulnerabilities:
            if self.scout_agent.ingest_vulnerability(vuln):
                vuln_success += 1
        
        # Ingest demo patches
        patch_success = 0
        for patch in self._demo_patches:
            if self.scout_agent.ingest_patch(patch):
                patch_success += 1
        
        logger.info(f"Demo knowledge base populated: {vuln_success} vulnerabilities, {patch_success} patches")
        return {"vulnerabilities": vuln_success, "patches": patch_success}

    def scan_demo_repository(self, repo_path: str = None) -> ScanResult:
        """Scan the demo repository with enhanced analysis"""
        if repo_path is None:
            repo_path = "/Users/iamwafula/GitHub/upload-worker/Auto_Security/repo_demo"
        
        logger.info(f"Starting enhanced scan of demo repository: {repo_path}")
        
        # First populate the knowledge base
        self.populate_demo_knowledge_base()
        
        # Perform the scan
        scan_result = self.scan_directory(repo_path)
        
        # Add demo-specific analysis
        scan_result = self._enhance_scan_results(scan_result)
        
        return scan_result

    def _enhance_scan_results(self, scan_result: ScanResult) -> ScanResult:
        """Enhance scan results with demo-specific analysis"""
        logger.info("Enhancing scan results with demo-specific analysis...")
        
        # Add package.json analysis
        package_analysis = self._analyze_package_json(scan_result.target_path)
        if package_analysis:
            # Add package vulnerabilities as findings
            for pkg_vuln in package_analysis:
                scan_result.findings.append(pkg_vuln)
                scan_result.total_findings += 1
        
        # Update severity counts
        for finding in scan_result.findings:
            severity = finding.severity
            scan_result.findings_by_severity[severity] = scan_result.findings_by_severity.get(severity, 0) + 1
        
        return scan_result

    def _analyze_package_json(self, repo_path: str) -> List:
        """Analyze package.json for vulnerable dependencies"""
        package_json_path = os.path.join(repo_path, "package.json")
        findings = []
        
        if not os.path.exists(package_json_path):
            return findings
        
        try:
            with open(package_json_path, 'r') as f:
                package_data = json.load(f)
            
            # Known vulnerable versions (simplified for demo)
            vulnerable_packages = {
                "express": {
                    "4.16.0": {
                        "severity": "HIGH",
                        "cve": "CVE-2023-12345",
                        "description": "Express.js 4.16.0 has known security vulnerabilities"
                    }
                },
                "mysql": {
                    "2.15.0": {
                        "severity": "MEDIUM", 
                        "cve": "CVE-2023-12348",
                        "description": "MySQL driver 2.15.0 has known security issues"
                    }
                },
                "jsonwebtoken": {
                    "7.4.1": {
                        "severity": "HIGH",
                        "cve": "CVE-2023-12349", 
                        "description": "JWT library 7.4.1 has critical vulnerabilities"
                    }
                },
                "bcrypt": {
                    "1.0.3": {
                        "severity": "CRITICAL",
                        "cve": "CVE-2023-12350",
                        "description": "Bcrypt 1.0.3 has critical security flaws"
                    }
                },
                "lodash": {
                    "4.17.4": {
                        "severity": "HIGH",
                        "cve": "CVE-2023-12351",
                        "description": "Lodash 4.17.4 has prototype pollution vulnerabilities"
                    }
                }
            }
            
            dependencies = package_data.get("dependencies", {})
            
            for package_name, version in dependencies.items():
                if package_name in vulnerable_packages:
                    package_vulns = vulnerable_packages[package_name]
                    if version in package_vulns:
                        vuln_info = package_vulns[version]
                        
                        # Create finding for vulnerable dependency
                        from vulnerability_scanner import VulnerabilityFinding
                        
                        finding = VulnerabilityFinding(
                            finding_id=f"pkg_{package_name}_{version}",
                            vulnerability_type="vulnerable_dependency",
                            severity=vuln_info["severity"],
                            confidence=0.95,
                            file_path=package_json_path,
                            line_number=0,
                            code_snippet=f'"{package_name}": "{version}"',
                            description=f"Vulnerable dependency: {package_name} {version} - {vuln_info['description']}",
                            evidence=f"{package_name}@{version}",
                            cve_matches=[{"cve_id": vuln_info["cve"]}]
                        )
                        
                        findings.append(finding)
            
        except Exception as e:
            logger.error(f"Error analyzing package.json: {e}")
        
        return findings

    def generate_demo_report(self, scan_result: ScanResult) -> str:
        """Generate a comprehensive demo report"""
        report = []
        report.append("=" * 100)
        report.append("DEMO REPOSITORY VULNERABILITY SCAN REPORT")
        report.append("=" * 100)
        report.append(f"Scan ID: {scan_result.scan_id}")
        report.append(f"Target: {scan_result.target_path}")
        report.append(f"Timestamp: {scan_result.scan_timestamp}")
        report.append(f"Duration: {scan_result.scan_duration:.2f} seconds")
        report.append(f"Total Findings: {scan_result.total_findings}")
        report.append("")
        
        # Executive Summary
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 50)
        critical_count = scan_result.findings_by_severity.get('CRITICAL', 0)
        high_count = scan_result.findings_by_severity.get('HIGH', 0)
        medium_count = scan_result.findings_by_severity.get('MEDIUM', 0)
        low_count = scan_result.findings_by_severity.get('LOW', 0)
        
        report.append(f"Critical vulnerabilities: {critical_count}")
        report.append(f"High vulnerabilities: {high_count}")
        report.append(f"Medium vulnerabilities: {medium_count}")
        report.append(f"Low vulnerabilities: {low_count}")
        report.append("")
        
        if critical_count > 0:
            report.append("⚠️  IMMEDIATE ACTION REQUIRED: Critical vulnerabilities found!")
        elif high_count > 0:
            report.append("⚠️  HIGH PRIORITY: High severity vulnerabilities require attention")
        else:
            report.append("✅ No critical or high severity vulnerabilities found")
        
        report.append("")
        
        # Detailed findings by category
        findings_by_type = {}
        for finding in scan_result.findings:
            vuln_type = finding.vulnerability_type
            if vuln_type not in findings_by_type:
                findings_by_type[vuln_type] = []
            findings_by_type[vuln_type].append(finding)
        
        report.append("DETAILED FINDINGS BY VULNERABILITY TYPE")
        report.append("-" * 50)
        
        for vuln_type, findings in findings_by_type.items():
            report.append(f"\n{vuln_type.upper().replace('_', ' ')} ({len(findings)} findings)")
            report.append("=" * (len(vuln_type) + 20))
            
            for i, finding in enumerate(findings, 1):
                report.append(f"\n{i}. {finding.severity} - {finding.file_path}:{finding.line_number}")
                report.append(f"   Confidence: {finding.confidence:.2f}")
                report.append(f"   Description: {finding.description}")
                report.append(f"   Evidence: {finding.evidence}")
                
                if finding.cve_matches:
                    report.append(f"   Related CVEs: {len(finding.cve_matches)} found")
                    for cve in finding.cve_matches[:2]:  # Show first 2 CVEs
                        cve_id = cve.get('metadata', {}).get('cve_id', 'Unknown')
                        report.append(f"     - {cve_id}")
                
                if finding.suggested_patches:
                    report.append(f"   Suggested Patches: {len(finding.suggested_patches)} available")
        
        # Recommendations
        report.append("\n\nSECURITY RECOMMENDATIONS")
        report.append("-" * 50)
        report.append("1. Update all vulnerable dependencies to latest secure versions")
        report.append("2. Implement input validation and sanitization for all user inputs")
        report.append("3. Use parameterized queries for all database operations")
        report.append("4. Implement proper authentication and authorization mechanisms")
        report.append("5. Add security headers and CORS configuration")
        report.append("6. Implement rate limiting and request validation")
        report.append("7. Regular security audits and dependency scanning")
        
        return '\n'.join(report)

# Example usage
if __name__ == "__main__":
    # Initialize demo scanner
    scanner = DemoRepositoryScanner()
    
    # Scan the demo repository
    print("Scanning demo repository...")
    scan_result = scanner.scan_demo_repository()
    
    # Generate comprehensive report
    print("Generating demo report...")
    demo_report = scanner.generate_demo_report(scan_result)
    
    # Save reports
    with open('demo_vulnerability_report.txt', 'w') as f:
        f.write(demo_report)
    
    # Also generate JSON report
    json_report = scanner.generate_report(scan_result, 'json')
    with open('demo_vulnerability_report.json', 'w') as f:
        f.write(json_report)
    
    print(f"Demo scan completed: {scan_result.total_findings} findings found")
    print("Reports saved: demo_vulnerability_report.txt, demo_vulnerability_report.json")
    
    # Print summary
    print("\n" + "="*50)
    print("SCAN SUMMARY")
    print("="*50)
    for severity, count in scan_result.findings_by_severity.items():
        print(f"{severity:>10}: {count:>3} findings")
