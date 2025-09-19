"""
Scout Agent Module

The Scout Agent is responsible for gathering threat intelligence and building a knowledge base
by scraping vulnerability feeds, CVE databases, and security patches from the web.
"""

from .scout_agent import ScoutAgent, VulnerabilityData, PatchData
from .mcp_stdio_client import BrightDataMCPStdioClient

__all__ = ['ScoutAgent', 'VulnerabilityData', 'PatchData', 'BrightDataMCPStdioClient']
