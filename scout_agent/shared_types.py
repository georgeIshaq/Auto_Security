"""
Shared data structures for the Auto_Security agentic workflow.
"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

@dataclass
class Finding:
    """Standardized structure for a security finding."""
    id: str
    type: str
    file_path: str
    line_number: int
    severity: str
    message: str
    evidence: str
    issue_number: Optional[int] = None
    vector_matches: Optional[List[Dict[str, Any]]] = None
    suggested_patches: Optional[List[Dict[str, Any]]] = None

    def to_dict(self):
        return asdict(self)
