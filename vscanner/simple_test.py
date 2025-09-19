#!/usr/bin/env python3
"""
Simple test for the vulnerability scanner without external dependencies
"""

import os
import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class VulnerabilityFinding:
    """Structure for vulnerability findings"""
    finding_id: str
    vulnerability_type: str
    severity: str
    confidence: float
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    evidence: str
    cve_matches: List[Dict] = None
    suggested_patches: List[Dict] = None
    remediation_priority: int = 0

class SimpleVulnerabilityScanner:
    """
    Simple vulnerability scanner without external dependencies
    """
    
    def __init__(self):
        """Initialize the vulnerability scanner"""
        
        # Vulnerability patterns for different languages
        self.patterns = {
            'javascript': {
                'sql_injection': [
                    r'query\s*\(\s*["\'].*\$.*["\']',  # String interpolation in queries
                    r'SELECT.*\+.*req\.',  # String concatenation in SQL
                    r'INSERT.*\+.*req\.',  # String concatenation in SQL
                    r'UPDATE.*\+.*req\.',  # String concatenation in SQL
                    r'DELETE.*\+.*req\.',  # String concatenation in SQL
                ],
                'xss': [
                    r'dangerouslySetInnerHTML',  # React XSS
                    r'innerHTML\s*=',  # Direct innerHTML assignment
                    r'document\.write\s*\(',  # document.write usage
                    r'eval\s*\(',  # eval() usage
                ],
                'command_injection': [
                    r'exec\s*\(',  # exec() usage
                    r'spawn\s*\(',  # spawn with user input
                    r'execSync\s*\(',  # execSync usage
                    r'shell\s*:\s*true',  # shell: true in child_process
                ],
                'path_traversal': [
                    r'fs\.readFile\s*\(.*req\.',  # File read with user input
                    r'fs\.createReadStream\s*\(.*req\.',  # File stream with user input
                    r'path\.join\s*\(.*req\.',  # Path join with user input
                ],
                'hardcoded_secrets': [
                    r'password\s*[:=]\s*["\'][^"\']{3,}["\']',  # Hardcoded passwords
                    r'api[_-]?key\s*[:=]\s*["\'][^"\']{10,}["\']',  # API keys
                    r'secret\s*[:=]\s*["\'][^"\']{10,}["\']',  # Secrets
                    r'token\s*[:=]\s*["\'][^"\']{10,}["\']',  # Tokens
                ],
                'insecure_random': [
                    r'Math\.random\s*\(',  # Math.random for security
                    r'crypto\.randomBytes\s*\(.*1\)',  # Insufficient random bytes
                ],
                'weak_crypto': [
                    r'crypto\.createHash\s*\(\s*["\']md5["\']',  # MD5 usage
                    r'crypto\.createHash\s*\(\s*["\']sha1["\']',  # SHA1 usage
                ]
            },
            'python': {
                'sql_injection': [
                    r'execute\s*\(\s*f["\'].*\{.*\}.*["\']',  # f-string in SQL
                    r'execute\s*\(\s*["\'].*%s.*["\']',  # String formatting in SQL
                    r'query\s*\(\s*["\'].*\+.*["\']',  # String concatenation
                ],
                'command_injection': [
                    r'os\.system\s*\(',  # os.system usage
                    r'subprocess\.call\s*\(.*shell\s*=\s*True',  # subprocess with shell
                    r'eval\s*\(',  # eval() usage
                    r'exec\s*\(',  # exec() usage
                ],
                'path_traversal': [
                    r'open\s*\(.*input',  # File open with user input
                    r'file\s*\(.*input',  # File with user input
                ],
                'deserialization': [
                    r'pickle\.loads\s*\(',  # Pickle deserialization
                    r'yaml\.load\s*\(',  # YAML load without safe_load
                ],
                'hardcoded_secrets': [
                    r'password\s*=\s*["\'][^"\']{3,}["\']',  # Hardcoded passwords
                    r'api_key\s*=\s*["\'][^"\']{10,}["\']',  # API keys
                    r'secret\s*=\s*["\'][^"\']{10,}["\']',  # Secrets
                ]
            }
        }
        
        # Severity mapping
        self.severity_map = {
            'sql_injection': 'HIGH',
            'xss': 'MEDIUM',
            'command_injection': 'CRITICAL',
            'path_traversal': 'HIGH',
            'hardcoded_secrets': 'CRITICAL',
            'insecure_random': 'MEDIUM',
            'weak_crypto': 'MEDIUM',
            'deserialization': 'HIGH'
        }
        
        # Confidence scoring based on pattern strength
        self.confidence_map = {
            'sql_injection': 0.9,
            'command_injection': 0.95,
            'path_traversal': 0.85,
            'hardcoded_secrets': 0.98,
            'xss': 0.8,
            'insecure_random': 0.7,
            'weak_crypto': 0.75,
            'deserialization': 0.9
        }

    def detect_vulnerabilities_in_file(self, file_path: str, content: str) -> List[VulnerabilityFinding]:
        """
        Detect vulnerabilities in a single file
        """
        findings = []
        file_extension = Path(file_path).suffix.lower()
        
        # Determine language based on file extension
        language = None
        if file_extension in ['.js', '.jsx', '.ts', '.tsx']:
            language = 'javascript'
        elif file_extension in ['.py']:
            language = 'python'
        else:
            print(f"Unsupported file type: {file_extension}")
            return findings
        
        if language not in self.patterns:
            return findings
        
        lines = content.split('\n')
        
        # Check each vulnerability pattern
        for vuln_type, patterns in self.patterns[language].items():
            for pattern in patterns:
                try:
                    regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                    matches = regex.finditer(content)
                    
                    for match in matches:
                        # Find line number
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Get code snippet (3 lines before and after)
                        start_line = max(0, line_num - 4)
                        end_line = min(len(lines), line_num + 3)
                        code_snippet = '\n'.join(lines[start_line:end_line])
                        
                        # Create finding
                        finding = VulnerabilityFinding(
                            finding_id=f"{Path(file_path).stem}_{vuln_type}_{line_num}_{hash(match.group())}",
                            vulnerability_type=vuln_type,
                            severity=self.severity_map.get(vuln_type, 'MEDIUM'),
                            confidence=self.confidence_map.get(vuln_type, 0.8),
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=code_snippet,
                            description=self._get_vulnerability_description(vuln_type),
                            evidence=match.group()
                        )
                        
                        findings.append(finding)
                        
                except re.error as e:
                    print(f"Regex error in pattern {pattern}: {e}")
                    continue
        
        return findings

    def _get_vulnerability_description(self, vuln_type: str) -> str:
        """Get human-readable description for vulnerability type"""
        descriptions = {
            'sql_injection': 'SQL Injection vulnerability detected - user input directly concatenated into SQL queries',
            'xss': 'Cross-Site Scripting (XSS) vulnerability detected - unsanitized user input rendered in HTML',
            'command_injection': 'Command Injection vulnerability detected - user input passed to system commands',
            'path_traversal': 'Path Traversal vulnerability detected - user input used in file path operations',
            'hardcoded_secrets': 'Hardcoded secrets detected - sensitive credentials stored in source code',
            'insecure_random': 'Insecure random number generation detected - insufficient entropy for security purposes',
            'weak_crypto': 'Weak cryptographic algorithm detected - deprecated or insecure hash functions used',
            'deserialization': 'Unsafe deserialization detected - potential for arbitrary code execution'
        }
        return descriptions.get(vuln_type, f'{vuln_type} vulnerability detected')

def test_scanner():
    """Test the vulnerability scanner"""
    print("=" * 60)
    print("TESTING VULNERABILITY SCANNER")
    print("=" * 60)
    
    # Create test code with vulnerabilities
    test_code = """
const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');

const app = express();

// SQL Injection vulnerability
app.get('/users/:id', (req, res) => {
  const query = \`SELECT * FROM users WHERE id = \${req.params.id}\`;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// XSS vulnerability
app.get('/profile/:username', (req, res) => {
  const username = req.params.username;
  res.send(\`<h1>Welcome \${username}</h1>\`);
});

// Command injection vulnerability
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(\`ping -c 1 \${host}\`, (error, stdout, stderr) => {
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

// Insecure random
const sessionId = Math.random().toString(36);

// Weak crypto
const hash = crypto.createHash('md5').update(password).digest('hex');
"""
    
    # Test the scanner
    scanner = SimpleVulnerabilityScanner()
    findings = scanner.detect_vulnerabilities_in_file("test.js", test_code)
    
    print(f"Found {len(findings)} vulnerabilities:")
    print()
    
    for i, finding in enumerate(findings, 1):
        print(f"{i}. {finding.vulnerability_type.upper()} - {finding.severity}")
        print(f"   File: {finding.file_path}:{finding.line_number}")
        print(f"   Confidence: {finding.confidence:.2f}")
        print(f"   Description: {finding.description}")
        print(f"   Evidence: {finding.evidence}")
        print(f"   Code snippet:")
        for line in finding.code_snippet.split('\n')[:3]:
            print(f"     {line}")
        print()
    
    # Test with Python code
    python_code = """
import os
import subprocess
import pickle

# Command injection
def ping_host(host):
    os.system(f'ping -c 1 {host}')

# SQL injection
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

# Deserialization
def load_data(data):
    return pickle.loads(data)

# Hardcoded secret
API_KEY = 'sk-1234567890abcdef'
"""
    
    print("Testing Python vulnerabilities...")
    python_findings = scanner.detect_vulnerabilities_in_file("test.py", python_code)
    
    print(f"Found {len(python_findings)} Python vulnerabilities:")
    print()
    
    for i, finding in enumerate(python_findings, 1):
        print(f"{i}. {finding.vulnerability_type.upper()} - {finding.severity}")
        print(f"   File: {finding.file_path}:{finding.line_number}")
        print(f"   Evidence: {finding.evidence}")
        print()
    
    total_findings = len(findings) + len(python_findings)
    print(f"Total vulnerabilities found: {total_findings}")
    
    if total_findings > 0:
        print("✅ Vulnerability scanner is working correctly!")
        return True
    else:
        print("❌ No vulnerabilities detected - scanner may not be working")
        return False

if __name__ == "__main__":
    test_scanner()
