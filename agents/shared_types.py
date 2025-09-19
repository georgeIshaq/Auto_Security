"""
Shared data structures for the Auto_Security agentic workflow.
"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

@dataclass
class Finding:
    """
    Standardized structure for a security finding.
    This is used to pass information between the Pentest, Scout, and Triage agents.
    """
    id: str
    type: str
    file_path: str
    line_number: int
    confidence: str  # e.g., 'High', 'Medium', 'Low'
    severity: str    # e.g., 'Critical', 'High', 'Medium', 'Low'
    message: str
    evidence: str
    issue_number: Optional[int] = None
    # Enriched data from Scout Agent
    vector_matches: List[Dict[str, Any]] = None
    suggested_patches: List[Dict[str, Any]] = None

    def to_dict(self):
        """Convert the dataclass instance to a dictionary."""
        return asdict(self)
