#!/usr/bin/env python3
"""
Vulnerability Scanner CLI Tool

A command-line interface for running vulnerability scans on codebases.
"""

import argparse
import sys
import os
from pathlib import Path

from vulnerability_scanner import VulnerabilityScanner
from demo_scanner import DemoRepositoryScanner
from scout_agent import ScoutAgent

def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description="Vulnerability Scanner - Detect security vulnerabilities in codebases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan demo repository
  python scan_cli.py --demo

  # Scan specific directory
  python scan_cli.py --target /path/to/code

  # Scan with custom output format
  python scan_cli.py --target /path/to/code --format html

  # Scan with verbose output
  python scan_cli.py --target /path/to/code --verbose
        """
    )
    
    # Target selection
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        '--demo', 
        action='store_true',
        help='Scan the demo repository'
    )
    target_group.add_argument(
        '--target', '-t',
        type=str,
        help='Target directory or file to scan'
    )
    
    # Output options
    parser.add_argument(
        '--format', '-f',
        choices=['json', 'html', 'text'],
        default='text',
        help='Output format for the report (default: text)'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Output file path (default: vulnerability_report.{format})'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--no-ai',
        action='store_true',
        help='Disable AI-powered context (faster but less detailed)'
    )
    
    # File type options
    parser.add_argument(
        '--extensions',
        nargs='+',
        default=['.js', '.jsx', '.ts', '.tsx', '.py'],
        help='File extensions to scan (default: .js .jsx .ts .tsx .py)'
    )
    
    args = parser.parse_args()
    
    # Set up logging
    import logging
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)
    
    try:
        # Determine target path
        if args.demo:
            target_path = "/Users/iamwafula/GitHub/upload-worker/Auto_Security/repo_demo"
            if not os.path.exists(target_path):
                print(f"Error: Demo repository not found at {target_path}")
                sys.exit(1)
        else:
            target_path = args.target
            if not os.path.exists(target_path):
                print(f"Error: Target path does not exist: {target_path}")
                sys.exit(1)
        
        # Initialize scanner
        if args.demo:
            print("Initializing demo scanner...")
            scanner = DemoRepositoryScanner()
            scan_result = scanner.scan_demo_repository(target_path)
        else:
            print("Initializing vulnerability scanner...")
            if args.no_ai:
                scanner = VulnerabilityScanner(scout_agent=None)
            else:
                scout_agent = ScoutAgent()
                scanner = VulnerabilityScanner(scout_agent)
                print("Populating knowledge base...")
                scout_agent.populate_knowledge_base(vuln_limit=5, patch_limit=3)
            
            scan_result = scanner.scan_directory(target_path, args.extensions)
        
        # Generate report
        print(f"Generating {args.format} report...")
        if args.demo and hasattr(scanner, 'generate_demo_report'):
            report_content = scanner.generate_demo_report(scan_result)
        else:
            report_content = scanner.generate_report(scan_result, args.format)
        
        # Determine output file
        if args.output:
            output_file = args.output
        else:
            if args.demo:
                output_file = f"demo_vulnerability_report.{args.format}"
            else:
                output_file = f"vulnerability_report.{args.format}"
        
        # Write report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        # Print summary
        print("\n" + "="*60)
        print("SCAN COMPLETED")
        print("="*60)
        print(f"Target: {target_path}")
        print(f"Total findings: {scan_result.total_findings}")
        print(f"Scan duration: {scan_result.scan_duration:.2f} seconds")
        print(f"Report saved: {output_file}")
        
        if scan_result.findings_by_severity:
            print("\nFindings by severity:")
            for severity, count in scan_result.findings_by_severity.items():
                print(f"  {severity:>10}: {count:>3} findings")
        
        # Show top findings
        if scan_result.findings:
            print(f"\nTop 5 findings:")
            for i, finding in enumerate(scan_result.findings[:5], 1):
                print(f"  {i}. {finding.severity} - {finding.vulnerability_type} in {finding.file_path}:{finding.line_number}")
        
        # Exit with appropriate code
        critical_count = scan_result.findings_by_severity.get('CRITICAL', 0)
        high_count = scan_result.findings_by_severity.get('HIGH', 0)
        
        if critical_count > 0:
            print(f"\n⚠️  {critical_count} critical vulnerabilities found!")
            sys.exit(2)
        elif high_count > 0:
            print(f"\n⚠️  {high_count} high severity vulnerabilities found!")
            sys.exit(1)
        else:
            print("\n✅ No critical or high severity vulnerabilities found!")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
