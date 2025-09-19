"""
Vulnerability Report Parser

This script reads a text-based vulnerability scan report and parses it
into a structured list of Finding objects for the Triage Agent to process.
"""

import re
import logging
from typing import List, Optional
# Adjust import path to be relative to the project root for broader usability
from scout_agent.shared_types import Finding

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ReportParser:
    """
    Parses a vulnerability report and extracts actionable findings.
    """

    def parse(self, report_path: str) -> List[Finding]:
        """
        Reads a report file and returns a list of Finding objects.

        :param report_path: The path to the vulnerability_report.text file.
        :return: A list of structured Finding objects.
        """
        findings: List[Finding] = []
        try:
            with open(report_path, 'r') as f:
                content = f.read()
        except FileNotFoundError:
            logger.error(f"Report file not found at path: {report_path}")
            return findings

        # Split the report into individual finding blocks
        finding_blocks = re.split(r'\n\d+\.\s', content)
        
        for i, block in enumerate(finding_blocks[1:], 1):
            finding = self._parse_block(block, i)
            if finding:
                findings.append(finding)

        logger.info(f"Parsed {len(findings)} findings from the report.")
        return findings

    def _parse_block(self, block: str, finding_id: int) -> Optional[Finding]:
        """
        Parses a single vulnerability block from the report.
        """
        try:
            header_match = re.search(r'(.+?) - (\w+)', block)
            if not header_match: return None
            vuln_type = header_match.group(1).strip()
            severity = header_match.group(2).strip()

            file_match = re.search(r'File:\s*(.+)', block)
            line_number = 0
            file_path_full = file_match.group(1).strip() if file_match else "Unknown"
            if ':' in file_path_full:
                parts = file_path_full.split(':')
                file_path = parts[0]
                try: line_number = int(parts[1])
                except (ValueError, IndexError): pass
            else:
                file_path = file_path_full
            
            finding = Finding(
                id=f"finding_{finding_id}",
                type=vuln_type,
                file_path=file_path,
                line_number=line_number,
                severity=severity,
                message=re.search(r'Description:\s*(.+)', block).group(1).strip(),
                evidence=re.search(r'Evidence:\s*(.+)', block).group(1).strip()
            )
            return finding
        except Exception as e:
            logger.error(f"Failed to parse finding block #{finding_id}: {e}")
            return None
